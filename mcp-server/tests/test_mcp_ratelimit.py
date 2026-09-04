"""Rate limiting tests for MCP Server."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig
from app.main import create_app
from app.db import TokenStore
from app.mcp_ratelimit import RateLimiter


@pytest.fixture()
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def app_config(tmp_dir: Path) -> AppConfig:
    return AppConfig(
        config_path=tmp_dir / "config.yml",
        servers=(
            ServerConfig(id="dev-web-01", name="Dev Web 01", url="http://127.0.0.1:1", env="development"),
        ),
        agent=AgentConfig(timeout_seconds=2.0, tls_verify=False),
        console=ConsoleConfig(
            data_dir=str(tmp_dir),
            require_approval=False,
            mcp_audit=False,
            rate_limit_per_minute=60,
            rate_limit_burst=5,
        ),
    )


@pytest.fixture()
def client(app_config, store):
    app = create_app(app_config, store=store)
    return TestClient(app)


@pytest.fixture()
def store(tmp_dir):
    return TokenStore(tmp_dir / "tokens.db")


class TestRateLimiter:
    """Unit tests for the RateLimiter class."""

    def test_allows_within_burst(self):
        limiter = RateLimiter(per_minute=60, burst=5)
        for _ in range(5):
            assert limiter.allow("client1") is True

    def test_blocks_after_burst_exceeded(self):
        limiter = RateLimiter(per_minute=60, burst=3)
        assert limiter.allow("client1") is True
        assert limiter.allow("client1") is True
        assert limiter.allow("client1") is True
        assert limiter.allow("client1") is False

    def test_separate_clients_independent(self):
        limiter = RateLimiter(per_minute=60, burst=2)
        assert limiter.allow("client1") is True
        assert limiter.allow("client1") is True
        assert limiter.allow("client1") is False
        assert limiter.allow("client2") is True

    def test_tokens_regenerate_over_time(self):
        limiter = RateLimiter(per_minute=600, burst=1)
        assert limiter.allow("client1") is True
        assert limiter.allow("client1") is False

    def test_cleanup_removes_stale_entries(self):
        limiter = RateLimiter(per_minute=60, burst=5)
        limiter.allow("client1")
        limiter.allow("client2")
        assert len(limiter._visitors) == 2
        limiter.cleanup(max_age_seconds=-1)
        assert len(limiter._visitors) == 0

    def test_zero_rate_disabled(self):
        limiter = RateLimiter(per_minute=0, burst=0)
        assert limiter.per_minute == 1
        assert limiter.burst == 1


class TestRateLimitMiddleware:
    """Integration tests for rate limiting middleware."""

    def test_allows_normal_traffic(self, client):
        res = client.get("/api/meta")
        assert res.status_code == 200

    def test_returns_429_when_rate_exceeded(self, app_config, store):
        app_config = AppConfig(
            config_path=app_config.config_path,
            servers=app_config.servers,
            agent=app_config.agent,
            console=ConsoleConfig(
                data_dir=app_config.console.data_dir,
                require_approval=False,
                mcp_audit=False,
                rate_limit_per_minute=60,
                rate_limit_burst=3,
            ),
        )
        app = create_app(app_config, store=store)
        client = TestClient(app)
        assert client.get("/api/meta").status_code == 200
        assert client.get("/api/meta").status_code == 200
        assert client.get("/api/meta").status_code == 200
        res = client.get("/api/meta")
        assert res.status_code == 429
        assert res.headers.get("Retry-After") == "60"

    def test_rate_limit_disabled_when_zero(self, app_config, store):
        app_config = AppConfig(
            config_path=app_config.config_path,
            servers=app_config.servers,
            agent=app_config.agent,
            console=ConsoleConfig(
                data_dir=app_config.console.data_dir,
                require_approval=False,
                mcp_audit=False,
                rate_limit_per_minute=0,
                rate_limit_burst=0,
            ),
        )
        app = create_app(app_config, store=store)
        client = TestClient(app)
        for _ in range(20):
            assert client.get("/api/meta").status_code == 200
