"""Tests for mock_agent policy engine, rate limiter, and audit logger."""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tools.mock_agent import (
    PolicyEngine, RateLimiter, AuditLogger, Scope, build_app,
)


class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine(
            commands=["systemctl status", "uptime"],
            services=["nginx", "docker"],
            allowed_paths=["/etc/os-release"],
            write_paths=["/var/log/app.log"],
        )
        self.engine.add_token("ro-token", scope=Scope.READONLY, files=["/etc/os-release"])
        self.engine.add_token("op-token", scope=Scope.OPERATOR,
                             commands=["systemctl status"], services=["nginx"])
        self.engine.add_token("disabled-token", scope=Scope.OPERATOR, disabled=True)

    def test_readonly_can_read_allowed_file(self):
        ok, _ = self.engine.can_read_file("ro-token", "/etc/os-release")
        assert ok is True

    def test_readonly_cannot_read_denied_file(self):
        ok, reason = self.engine.can_read_file("ro-token", "/etc/shadow")
        assert ok is False

    def test_readonly_cannot_run_command(self):
        ok, reason = self.engine.can_run_command("ro-token", "systemctl status")
        assert ok is False
        assert "operator scope required" in reason

    def test_readonly_cannot_manage_service(self):
        ok, reason = self.engine.can_manage_service("ro-token", "nginx")
        assert ok is False

    def test_readonly_cannot_write_file(self):
        ok, reason = self.engine.can_write_file("ro-token", "/var/log/app.log")
        assert ok is False

    def test_operator_can_run_allowed_command(self):
        ok, _ = self.engine.can_run_command("op-token", "systemctl status")
        assert ok is True

    def test_operator_cannot_run_disallowed_command(self):
        ok, reason = self.engine.can_run_command("op-token", "rm -rf /")
        assert ok is False
        assert "not in token allowlist" in reason

    def test_operator_can_manage_allowed_service(self):
        ok, _ = self.engine.can_manage_service("op-token", "nginx")
        assert ok is True

    def test_operator_cannot_manage_disallowed_service(self):
        ok, _ = self.engine.can_manage_service("op-token", "mysql")
        assert ok is False

    def test_operator_can_write_allowed_path(self):
        ok, _ = self.engine.can_write_file("op-token", "/var/log/app.log")
        assert ok is True

    def test_operator_cannot_write_denied_path(self):
        ok, _ = self.engine.can_write_file("op-token", "/etc/shadow")
        assert ok is False

    def test_disabled_token_denied_everything(self):
        assert self.engine.can_read_file("disabled-token", "/etc/os-release")[0] is False
        assert self.engine.can_run_command("disabled-token", "uptime")[0] is False

    def test_unknown_token_denied(self):
        ok, reason = self.engine.can_read_file("no-such-token", "/etc/os-release")
        assert ok is False
        assert "unknown or disabled" in reason

    def test_path_traversal_blocked(self):
        ok, _ = self.engine.can_read_file("op-token", "/etc/../etc/shadow")
        assert ok is False

    def test_path_normalization_relative(self):
        ok, _ = self.engine.can_read_file("op-token", "etc/os-release")
        assert ok is True

    def test_token_specific_allowlist_takes_precedence(self):
        ok, _ = self.engine.can_read_service("op-token", "nginx")
        assert ok is True
        ok, _ = self.engine.can_read_service("op-token", "docker")
        assert ok is False

    def test_is_subpath_exact(self):
        assert PolicyEngine._is_subpath("/a/b", "/a/b") is True

    def test_is_subpath_nested(self):
        assert PolicyEngine._is_subpath("/a/b/c", "/a/b") is True

    def test_is_subpath_not_prefix_false_positive(self):
        assert PolicyEngine._is_subpath("/var/logistics", "/var/log") is False


class TestRateLimiter:
    def test_allows_within_burst(self):
        rl = RateLimiter(rate=10.0, burst=5)
        for _ in range(5):
            assert rl.consume("key") is True

    def test_blocks_after_burst_exhausted(self):
        rl = RateLimiter(rate=0.1, burst=2)
        assert rl.consume("key") is True
        assert rl.consume("key") is True
        assert rl.consume("key") is False

    def test_time_to_wait_positive_when_exhausted(self):
        rl = RateLimiter(rate=0.1, burst=1)
        rl.consume("key")
        wait = rl.time_to_wait("key")
        assert wait > 0

    def test_refills_over_time(self):
        rl = RateLimiter(rate=100.0, burst=1)
        rl.consume("key")
        assert rl.consume("key") is False
        time.sleep(0.02)
        assert rl.consume("key") is True

    def test_separate_keys_independent(self):
        rl = RateLimiter(rate=0.1, burst=1)
        assert rl.consume("key1") is True
        assert rl.consume("key1") is False
        assert rl.consume("key2") is True


class TestAuditLogger:
    def test_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            audit = AuditLogger(log_dir=d)
            audit.log("test.action", token_id="tok-1", details={"k": "v"})
            audit.close()
            log_file = Path(d) / "audit.jsonl"
            assert log_file.exists()
            line = log_file.read_text().strip().split("\n")[-1]
            entry = json.loads(line)
            assert entry["action"] == "test.action"
            assert entry["token_id"] == "tok-1"
            assert entry["ok"] is True
            assert entry["details"] == {"k": "v"}
            assert "timestamp" in entry

    def test_writes_error_entry(self):
        with tempfile.TemporaryDirectory() as d:
            audit = AuditLogger(log_dir=d)
            audit.log("denied", token_id="tok-2", ok=False, error="nope")
            audit.close()
            entry = json.loads((Path(d) / "audit.jsonl").read_text().strip())
            assert entry["ok"] is False
            assert entry["error"] == "nope"


class TestMockApiWithPolicy:
    def setup_method(self):
        self.policy = PolicyEngine(
            commands=["uptime"],
            services=["nginx"],
            allowed_paths=["/etc/os-release"],
            write_paths=["/var/log/app.log"],
        )
        self.policy.add_token("op-tok", scope=Scope.OPERATOR)
        self.app = build_app(tokens=["op-tok"], policy=self.policy)
        self.client = TestClient(self.app)
        self.headers = {"Authorization": "Bearer op-tok"}

    def test_read_file_ok(self):
        r = self.client.get("/v1/files?path=/etc/os-release", headers=self.headers)
        assert r.status_code == 200

    def test_read_denied_file_returns_403(self):
        r = self.client.get("/v1/files?path=/etc/shadow", headers=self.headers)
        assert r.status_code == 403

    def test_execute_allowed_command(self):
        r = self.client.post("/v1/execute", json={"command": "uptime"}, headers=self.headers)
        assert r.status_code == 200

    def test_execute_disallowed_command_returns_403(self):
        r = self.client.post("/v1/execute", json={"command": "rm -rf /"}, headers=self.headers)
        assert r.status_code == 403

    def test_service_status_ok(self):
        r = self.client.get("/v1/services/nginx", headers=self.headers)
        assert r.status_code == 200

    def test_write_allowed_path(self):
        r = self.client.post("/v1/files?path=/var/log/app.log",
                             json={"content": "test"}, headers=self.headers)
        assert r.status_code == 200

    def test_write_denied_path_returns_403(self):
        r = self.client.post("/v1/files?path=/etc/shadow",
                             json={"content": "x"}, headers=self.headers)
        assert r.status_code == 403
    def test_rate_limiting(self):
        rl = RateLimiter(rate=0.5, burst=2)
        app = build_app(tokens=["rl-tok"], rate_limiter=rl)
        client = TestClient(app)
        h = {"Authorization": "Bearer rl-tok"}
        # burst of 2 allows first 2 requests
        assert client.get("/v1/system", headers=h).status_code == 200
        assert client.get("/v1/system", headers=h).status_code == 200
        # third request is rate limited
        assert client.get("/v1/system", headers=h).status_code == 429
