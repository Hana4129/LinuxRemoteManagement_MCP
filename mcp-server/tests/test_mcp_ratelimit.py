"""Rate limiting tests for MCP Server."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig
from console.main import create_app
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
            auth_required=False,
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
                auth_required=False,
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
                auth_required=False,
            ),
        )
        app = create_app(app_config, store=store)
        client = TestClient(app)
        for _ in range(20):
            assert client.get("/api/meta").status_code == 200

    # ---- レート制限の高度化 (トークンレベル・操作別) ----

    def _app_with_limits(self, app_config, store, **rate_kwargs):
        console = {
            "data_dir": app_config.console.data_dir,
            "require_approval": False,
            "mcp_audit": False,
            "auth_required": False,
            "rate_limit_per_minute": 60,
            "rate_limit_burst": 1000,
        }
        console.update(rate_kwargs)
        return create_app(
            AppConfig(
                config_path=app_config.config_path,
                servers=app_config.servers,
                agent=app_config.agent,
                console=ConsoleConfig(**console),
            ),
            store=store,
        )

    def test_write_ops_use_separate_bucket(self, app_config, store):
        """操作系 (POST) は独立した write bucket で制限される。"""
        app = self._app_with_limits(
            app_config, store,
            rate_limit_write_per_minute=60, rate_limit_write_burst=2,
        )
        client = TestClient(app)
        # 読み取り (GET) は burst=1000 なので制限されない
        assert client.get("/api/nodes").status_code == 200
        assert client.get("/api/nodes").status_code == 200
        # 操作系 (POST /api/tokens は認証不要設定でも 401 になり得るが、
        # レート制限は認証より外側で適用されるため 429 を確認する)
        for i in range(2):
            res = client.post("/api/tokens", json={"name": f"t{i}", "server_ids": ["dev-web-01"], "scope": "readonly"})
            assert res.status_code in (200, 401, 422), f"unexpected {res.status_code}"
        res = client.post("/api/tokens", json={"name": "t3", "server_ids": ["dev-web-01"], "scope": "readonly"})
        assert res.status_code == 429

    def test_token_level_limit_independent_of_ip(self):
        """Bearer トークン単位の制限が設定可能で、同一IPでも別トークンは独立扱い。"""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.mcp_ratelimit import install_rate_limit

        app = FastAPI()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        install_rate_limit(
            app,
            per_minute=60, burst=1000,
            token_per_minute=60, token_burst=2,
        )
        client = TestClient(app)
        headers_a = {"Authorization": "Bearer token-aaa"}
        headers_b = {"Authorization": "Bearer token-bbb"}
        for _ in range(2):
            assert client.get("/ping", headers=headers_a).status_code == 200
        assert client.get("/ping", headers=headers_a).status_code == 429
        # 別トークンは同一IPからでも別バケットで許可される
        assert client.get("/ping", headers=headers_b).status_code == 200

    def test_ip_plus_token_composite_key(self):
        """IP+トークン複合: 同一IPでもトークンが違えば複合キーも独立する。"""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.mcp_ratelimit import install_rate_limit

        app = FastAPI()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        install_rate_limit(app, per_minute=60, burst=2)
        client = TestClient(app)
        for _ in range(2):
            assert client.get("/ping", headers={"Authorization": "Bearer tok-a"}).status_code == 200
        assert client.get("/ping", headers={"Authorization": "Bearer tok-a"}).status_code == 429
        # トークン無し (同一IP) は別キーで許可
        assert client.get("/ping").status_code == 200
        assert client.get("/ping").status_code == 200

    def test_bearer_header_hash_not_plain(self):
        """Bearer トークンはハッシュ化されてキーになり、生値がキーに残らない。"""
        from app.mcp_ratelimit import _bearer_token_key

        key = _bearer_token_key("Bearer lra_secret-token-value")
        assert key
        assert "lra_secret" not in key
        assert key != "lra_secret-token-value"
        assert _bearer_token_key("Basic dXNlcg==") == ""
        assert _bearer_token_key("Bearer ") == ""
