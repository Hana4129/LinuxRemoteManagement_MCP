"""McpAudit (mcp_audit.py) の単体テスト。"""
from __future__ import annotations

import json

from app.mcp_audit import McpAudit, sanitize_params


def test_sanitize_params_masks_sensitive_keys():
    out = sanitize_params({"token": "lra_secret", "Authorization": "Bearer x", "path": "/etc/os-release"})
    assert out["token"] == "***"
    assert out["Authorization"] == "***"
    assert out["path"] == "/etc/os-release"


def test_sanitize_params_truncates_long_values():
    long = "a" * 500
    out = sanitize_params({"value": long})
    assert len(out["value"]) == 200 + 1  # 切り詰め + 省略記号
    assert out["value"].startswith("a" * 200)


def test_sanitize_params_empty_and_none():
    assert sanitize_params(None) == {}
    assert sanitize_params({}) == {}


def test_log_writes_jsonl_entries(audit: McpAudit):
    audit.log(actor="mcp:ci", action="get_system_info", server="dev-web-01", params={}, ok=True, duration_ms=12.34)
    audit.log(actor="mcp:ci", action="restart_service", server="dev-web-01",
              params={"service": "nginx", "token": "lra_x"}, ok=False, error_kind="approval_required")
    entries = audit.read_entries()
    assert len(entries) == 2
    first = entries[0]
    assert first["actor"] == "mcp:ci"
    assert first["action"] == "get_system_info"
    assert first["server"] == "dev-web-01"
    assert first["ok"] is True
    assert first["duration_ms"] == 12.3
    second = entries[1]
    assert second["ok"] is False
    assert second["error_kind"] == "approval_required"
    assert second["params"]["token"] == "***"  # 機密キーはマスクされる


def test_log_file_is_jsonl_format(tmp_dir, audit: McpAudit):
    audit.log(actor="mcp", action="list_servers", ok=True)
    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["action"] == "list_servers"


def test_disabled_audit_writes_nothing(tmp_dir):
    a = McpAudit(tmp_dir / "off.jsonl", enabled=False)
    a.log(actor="mcp", action="get_system_info", ok=True)
    assert not a.path.exists()
    a.close()


def test_close_is_idempotent(audit: McpAudit):
    audit.log(actor="mcp", action="x", ok=True)
    audit.close()
    audit.close()  # 2回呼んでもエラーにならない
