"""管理コンソールとMCP HTTPの認証テスト。"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.config import AgentConfig, AppConfig, ConsoleConfig, McpConfig, ServerConfig
from app.main import create_app
from app.mcp_http import create_mcp_http_app


def _config(tmp_path, *, username: str = "", password: str = "", admin_token: str = "") -> AppConfig:
    return AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(ServerConfig(id="dev", name="Dev", url="http://127.0.0.1:1"),),
        agent=AgentConfig(timeout_seconds=1, tls_verify=False, admin_token=admin_token),
        console=ConsoleConfig(
            data_dir=str(tmp_path),
            username=username,
            password=password,
            auth_required=True,
            mcp_http=False,
        ),
    )


def test_production_console_auth_requires_credentials(tmp_path, store):
    with pytest.raises(ValueError, match="username/password"):
        create_app(_config(tmp_path), store=store)


def test_console_basic_auth_is_required(tmp_path, store):
    app = create_app(_config(tmp_path, username="admin", password="secret"), store=store)
    client = TestClient(app)

    assert client.get("/api/meta").status_code == 401
    credentials = base64.b64encode(b"admin:secret").decode("ascii")
    response = client.get("/api/meta", headers={"Authorization": f"Basic {credentials}"})
    assert response.status_code == 200


def test_console_rejects_cross_origin_mutation(tmp_path, store):
    app = create_app(_config(tmp_path, username="admin", password="secret"), store=store)
    credentials = base64.b64encode(b"admin:secret").decode("ascii")
    with TestClient(app) as client:
        response = client.post(
            "/api/principals",
            json={"subject": "x", "display_name": "X", "role": "viewer"},
            headers={
                "Authorization": f"Basic {credentials}",
                "Origin": "https://evil.example",
            },
        )
    assert response.status_code == 403


def test_mcp_http_requires_active_bearer_token(tmp_path, store):
    config = _config(tmp_path, username="admin", password="secret")
    config = AppConfig(
        config_path=config.config_path,
        servers=config.servers,
        agent=config.agent,
        mcp=McpConfig(path="/mcp"),
        console=ConsoleConfig(
            data_dir=config.console.data_dir,
            username=config.console.username,
            password=config.console.password,
            auth_required=True,
            mcp_http=True,
        ),
    )
    record, raw = store.create_token(name="user-a", server_ids=["dev"], scope="readonly")
    app = create_mcp_http_app(config, store=store)
    with TestClient(app) as client:
        assert client.get("/mcp").status_code == 401
        assert client.get("/mcp", headers={"Authorization": "Bearer invalid"}).status_code == 401
        try:
            valid = client.get("/mcp", headers={"Authorization": f"Bearer {raw}"})
            assert valid.status_code != 401
        except RuntimeError as exc:
            assert "task group is not initialized" in str(exc).lower()

        store.revoke_token(record.id)
        assert client.get("/mcp", headers={"Authorization": f"Bearer {raw}"}).status_code == 401


def test_principal_permission_and_disable_revoke_access(tmp_path, store):
    config = _config(tmp_path, username="admin", password="secret")
    app = create_app(config, store=store)
    with TestClient(app) as client:
        headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
        principal = client.post(
            "/api/principals",
            json={"subject": "user-a", "display_name": "User A", "role": "viewer"},
            headers=headers,
        ).json()
        principal_id = principal["id"]
        assert client.post(
            f"/api/principals/{principal_id}/permissions",
            json={"server_id": "dev", "scope": "readonly"},
            headers=headers,
        ).status_code == 200
        token = client.post(
            "/api/tokens",
            json={"name": "user-a-token", "principal_id": principal_id, "server_ids": ["dev"], "scope": "readonly"},
            headers=headers,
        ).json()
        assert token["record"]["principal_id"] == principal_id
        assert client.post(f"/api/principals/{principal_id}/disable", headers=headers).status_code == 200

    assert store.get_by_raw(token["token"]) is not None


def test_agent_credentials_are_separate_and_revocable(tmp_path, store, monkeypatch):
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        response = client.post(
            "/api/agent-credentials",
            json={"server_id": "dev", "name": "dev-agent", "token": "agent-secret", "agent_token_id": "agent-1"},
            headers=headers,
        )
        assert response.status_code == 200
        credential_id = response.json()["credential"]["id"]
        assert "token" not in response.json()["credential"]
        monkeypatch.setattr(
            "httpx.post",
            lambda *args, **kwargs: type("Response", (), {"status_code": 200})(),
        )
        assert client.post(f"/api/agent-credentials/{credential_id}/revoke", headers=headers).json()["revoked"]
    assert store.find_agent_credential("dev") is None


def test_oidc_subject_must_be_provisioned(tmp_path, store, monkeypatch):
    config = _config(tmp_path)
    config = AppConfig(
        config_path=config.config_path,
        servers=config.servers,
        agent=config.agent,
        console=ConsoleConfig(
            data_dir=config.console.data_dir,
            auth_required=True,
            auth_mode="oidc",
            oidc_issuer="https://issuer.example",
            oidc_audience="lrm",
            oidc_jwks_url="https://issuer.example/keys",
            mcp_http=False,
        ),
    )

    class FakeValidator:
        def __init__(self, issuer, audience, jwks_url):
            pass

        def validate(self, raw_token):
            return {"sub": raw_token}

    monkeypatch.setattr("app.main.OidcValidator", FakeValidator)
    app = create_app(config, store=store)
    with TestClient(app) as client:
        assert client.get("/api/meta", headers={"Authorization": "Bearer unknown"}).status_code == 403
        store.create_principal("known-sub", "Known User", "viewer")


def test_oidc_missing_issuer_rejected(tmp_path, store):
    """issuer未設定時にOIDCモードが拒否されることを確認"""
    config = _config(tmp_path)
    config = AppConfig(
        config_path=config.config_path,
        servers=config.servers,
        agent=config.agent,
        console=ConsoleConfig(
            data_dir=config.console.data_dir,
            auth_required=True,
            auth_mode="oidc",
            oidc_issuer="",  # 未設定
            oidc_audience="lrm",
            oidc_jwks_url="https://issuer.example/keys",
            mcp_http=False,
        ),
    )
    with pytest.raises(ValueError, match="issuer"):
        create_app(config, store=store)


def test_oidc_missing_audience_rejected(tmp_path, store):
    """audience未設定時にOIDCモードが拒否されることを確認"""
    config = _config(tmp_path)
    config = AppConfig(
        config_path=config.config_path,
        servers=config.servers,
        agent=config.agent,
        console=ConsoleConfig(
            data_dir=config.console.data_dir,
            auth_required=True,
            auth_mode="oidc",
            oidc_issuer="https://issuer.example",
            oidc_audience="",  # 未設定
            oidc_jwks_url="https://issuer.example/keys",
            mcp_http=False,
        ),
    )
    with pytest.raises(ValueError, match="audience"):
        create_app(config, store=store)


def test_oidc_missing_jwks_url_rejected(tmp_path, store):
    """jwks_url未設定時にOIDCモードが拒否されることを確認"""
    config = _config(tmp_path)
    config = AppConfig(
        config_path=config.config_path,
        servers=config.servers,
        agent=config.agent,
        console=ConsoleConfig(
            data_dir=config.console.data_dir,
            auth_required=True,
            auth_mode="oidc",
            oidc_issuer="https://issuer.example",
            oidc_audience="lrm",
            oidc_jwks_url="",  # 未設定
            mcp_http=False,
        ),
    )
    with pytest.raises(ValueError, match="jwks_url"):
        create_app(config, store=store)


def test_oidc_invalid_jwks_url_rejected(tmp_path, store, monkeypatch):
    """不正なJWKS URL時にエラーになることを確認"""
    config = _config(tmp_path)
    config = AppConfig(
        config_path=config.config_path,
        servers=config.servers,
        agent=config.agent,
        console=ConsoleConfig(
            data_dir=config.console.data_dir,
            auth_required=True,
            auth_mode="oidc",
            oidc_issuer="https://issuer.example",
            oidc_audience="lrm",
            oidc_jwks_url="http://insecure.example/keys",  # HTTP (HTTPSでない)
            mcp_http=False,
        ),
    )
    with pytest.raises(ValueError, match="https"):
        create_app(config, store=store)

        assert client.get("/api/meta", headers={"Authorization": "Bearer known-sub"}).status_code == 200
