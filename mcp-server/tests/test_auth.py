"""管理コンソールとMCP HTTPの認証テスト。"""
from __future__ import annotations

import base64

import httpx
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


def test_principal_viewer_cannot_create_principal(tmp_path, store):
    """viewerロールのMCPトークンではprincipalを作成できない (403)"""
    config = _config(tmp_path, username="admin", password="secret")
    app = create_app(config, store=store)
    admin_headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        principal = client.post(
            "/api/principals",
            json={"subject": "viewer-user", "display_name": "Viewer User", "role": "viewer"},
            headers=admin_headers,
        ).json()
        token = client.post(
            "/api/tokens",
            json={
                "name": "viewer-token",
                "principal_id": principal["id"],
                "server_ids": ["dev"],
                "scope": "readonly",
            },
            headers=admin_headers,
        ).json()
        response = client.post(
            "/api/principals",
            json={"subject": "another-user", "display_name": "Another User", "role": "viewer"},
            headers={"Authorization": f"Bearer {token['token']}"},
        )
        assert response.status_code == 403


def test_principal_operator_cannot_create_principal(tmp_path, store):
    """operatorロールのMCPトークンでもprincipalを作成できない (403)"""
    config = _config(tmp_path, username="admin", password="secret")
    app = create_app(config, store=store)
    admin_headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        principal = client.post(
            "/api/principals",
            json={"subject": "operator-user", "display_name": "Operator User", "role": "operator"},
            headers=admin_headers,
        ).json()
        token = client.post(
            "/api/tokens",
            json={
                "name": "operator-token",
                "principal_id": principal["id"],
                "server_ids": ["dev"],
                "scope": "operator",
            },
            headers=admin_headers,
        ).json()
        response = client.post(
            "/api/principals",
            json={"subject": "another-user", "display_name": "Another User", "role": "viewer"},
            headers={"Authorization": f"Bearer {token['token']}"},
        )
        assert response.status_code == 403


def test_principal_admin_token_can_create_principal(tmp_path, store):
    """adminロールに紐づくMCPトークンならprincipalを作成できる (200)"""
    config = _config(tmp_path, username="admin", password="secret")
    app = create_app(config, store=store)
    admin_headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        principal = client.post(
            "/api/principals",
            json={"subject": "admin-user", "display_name": "Admin User", "role": "admin"},
            headers=admin_headers,
        ).json()
        token = client.post(
            "/api/tokens",
            json={
                "name": "admin-token",
                "principal_id": principal["id"],
                "server_ids": ["dev"],
                "scope": "operator",
            },
            headers=admin_headers,
        ).json()
        response = client.post(
            "/api/principals",
            json={"subject": "new-admin", "display_name": "New Admin", "role": "viewer"},
            headers={"Authorization": f"Bearer {token['token']}"},
        )
        assert response.status_code == 200
        assert response.json()["role"] == "viewer"


def test_mcp_token_auth_sets_principal(tmp_path, store):
    """MCPトークン認証: 無効トークンは401、principal紐づきトークンは認証される"""
    config = _config(tmp_path, username="admin", password="secret")
    app = create_app(config, store=store)
    admin_headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        # 無効なトークンは401 (principal未設定のまま管理APIをバイパスできない)
        assert client.get("/api/meta", headers={"Authorization": "Bearer invalid"}).status_code == 401
        # principalに紐づく有効なトークンは認証される
        principal = client.post(
            "/api/principals",
            json={"subject": "test-user", "display_name": "Test User", "role": "viewer"},
            headers=admin_headers,
        ).json()
        token = client.post(
            "/api/tokens",
            json={
                "name": "test-token",
                "principal_id": principal["id"],
                "server_ids": ["dev"],
                "scope": "readonly",
            },
            headers=admin_headers,
        ).json()
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {token['token']}"})
        assert response.status_code == 200


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


def test_agent_credential_registered_from_env_var(tmp_path, store, monkeypatch):
    """env:NAME 形式で環境変数からトークンを解決して登録できる (生値をリクエストに載せない)。"""
    monkeypatch.setenv("LRM_TEST_AGENT_TOKEN", "secret-from-env")
    app = create_app(_config(tmp_path, username="admin", password="secret"), store=store)
    headers = _admin_headers()
    with TestClient(app) as client:
        response = client.post(
            "/api/agent-credentials",
            json={"server_id": "dev", "name": "env-agent", "token": "env:LRM_TEST_AGENT_TOKEN", "agent_token_id": "agent-env"},
            headers=headers,
        )
        assert response.status_code == 200
        # レスポンスに生値は出ない
        assert "token" not in response.json()["credential"]
    found = store.find_agent_credential("dev")
    assert found is not None and found.token_raw == "secret-from-env"


def test_agent_credential_env_missing_is_rejected(tmp_path, store, monkeypatch):
    """未設定の環境変数を参照すると400で拒否される。"""
    monkeypatch.delenv("LRM_MISSING_TOKEN", raising=False)
    app = create_app(_config(tmp_path, username="admin", password="secret"), store=store)
    headers = _admin_headers()
    with TestClient(app) as client:
        res = client.post(
            "/api/agent-credentials",
            json={"server_id": "dev", "name": "env-agent", "token": "env:LRM_MISSING_TOKEN", "agent_token_id": "agent-env"},
            headers=headers,
        )
        assert res.status_code == 400


def test_agent_credential_env_empty_is_rejected(tmp_path, store, monkeypatch):
    """空の環境変数を参照すると400で拒否される。"""
    monkeypatch.setenv("LRM_EMPTY_TOKEN", "")
    app = create_app(_config(tmp_path, username="admin", password="secret"), store=store)
    headers = _admin_headers()
    with TestClient(app) as client:
        res = client.post(
            "/api/agent-credentials",
            json={"server_id": "dev", "name": "env-agent", "token": "env:LRM_EMPTY_TOKEN", "agent_token_id": "agent-env"},
            headers=headers,
        )
        assert res.status_code == 400


def test_agent_credential_generate_returns_raw_once(tmp_path, store):
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        response = client.post(
            "/api/agent-credentials/generate",
            json={"server_id": "dev", "name": "gen-agent", "agent_token_id": "agent-gen"},
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        # 生tokenは一度だけ返す (CSPRNG生成)
        assert body["token"].startswith("lra_")
        assert len(body["token"]) > 40
        assert "token" not in body["credential"]
        # 一覧に生値を再表示しない
        listing = client.get("/api/agent-credentials", headers=headers).json()
        assert all("token" not in c for c in listing["credentials"])
        assert all(body["token"] != c.get("token_raw", "") for c in listing["credentials"])
    # ストア内では生値を保持し、findで利用できる
    found = store.find_agent_credential("dev")
    assert found is not None and found.token_raw == body["token"]


def test_agent_credential_rotation_creates_new_with_grace(tmp_path, store):
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        created = client.post(
            "/api/agent-credentials",
            json={"server_id": "dev", "name": "rot-agent", "token": "old-secret", "agent_token_id": "agent-rot"},
            headers=headers,
        ).json()["credential"]
        old_id = created["id"]
        response = client.post(
            f"/api/agent-credentials/{old_id}/rotate",
            json={"grace_period_days": 3},
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        new_id = body["credential"]["id"]
        # 新しい生tokenが一度だけ返る
        assert body["token"].startswith("lra_") and body["token"] != "old-secret"
        # 旧credentialはグラ期間中はenabledのまま残る
        assert body["old_credential"]["id"] == old_id
        assert body["old_credential"]["grace_ends_at"] is not None
        assert body["old_credential"]["enabled"] is True
        old = store.get_agent_credential(old_id)
        assert old.enabled and old.grace_ends_at is not None
        # findは新しいcredentialを返す (rowid DESCで同一秒の新規を優先)
        assert store.find_agent_credential("dev").id == new_id
        assert store.find_agent_credential("dev").token_raw == body["token"]
        # 履歴が記録される
        history = client.get(f"/api/agent-credentials/{old_id}/rotations", headers=headers).json()
        assert history["rotations"][0]["old_credential_id"] == old_id
        assert history["rotations"][0]["new_credential_id"] == new_id
        assert history["rotations"][0]["rotated_by"]


def test_agent_credential_rotation_rejects_revoked(tmp_path, store):
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        credential_id = store.create_agent_credential("dev", "revoked-agent", "raw-secret", agent_token_id="agent-x").id
        store.revoke_agent_credential(credential_id)
        response = client.post(
            f"/api/agent-credentials/{credential_id}/rotate",
            json={"grace_period_days": 7},
            headers=headers,
        )
        assert response.status_code == 400
        # 404 も確認
        assert client.post("/api/agent-credentials/agt_missing/rotate", json={}, headers=headers).status_code == 404


def test_agent_credential_grace_expiry_disables_old(tmp_path, store):
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}
    with TestClient(app) as client:
        old_id = store.create_agent_credential("dev", "grace-agent", "old-secret", agent_token_id="agent-g").id
        body = client.post(
            f"/api/agent-credentials/{old_id}/rotate",
            json={"grace_period_days": 7},
            headers=headers,
        ).json()
        new_id = body["credential"]["id"]
        # グラ期間を過去に設定して期限切れを再現する
        with store._lock, store._connect() as conn:
            conn.execute("UPDATE agent_credentials SET grace_ends_at = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", old_id))
        old = store.get_agent_credential(old_id)
        # グラ期間経過後は旧credentialは使用不可
        assert old.enabled and old.active is False
        assert store.find_agent_credential("dev").id == new_id
        # cleanup で完全失効 (enabled=0)
        cleaned = client.post("/api/agent-credentials/cleanup-grace-periods", headers=headers).json()["cleaned"]
        assert cleaned == 1
        assert store.get_agent_credential(old_id).enabled is False
        assert client.post("/api/agent-credentials/cleanup-grace-periods", headers=headers).json()["cleaned"] == 0


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


def test_oidc_known_subject_allowed(tmp_path, store, monkeypatch):
    """登録済み subject のOIDCトークンでアクセスできることを確認"""
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
    store.create_principal("known-sub", "Known User", "viewer")
    app = create_app(config, store=store)
    with TestClient(app) as client:
        assert client.get("/api/meta", headers={"Authorization": "Bearer known-sub"}).status_code == 200


# ---------------------------------------------------------------------------
# Agent失効同期の障害時運用 (fail-closed / 冪等性 / 再送)
# ---------------------------------------------------------------------------


def _admin_headers() -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}


def _register_agent_credential(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/api/agent-credentials",
        json={"server_id": "dev", "name": "dev-agent", "token": "agent-secret", "agent_token_id": "agent-1"},
        headers=headers,
    )
    assert response.status_code == 200
    return response.json()["credential"]["id"]


def _agent_down(*args, **kwargs):
    raise httpx.ConnectError("connection refused")


def _agent_ok(*args, **kwargs):
    return type("Response", (), {"status_code": 200})()


def test_revoke_agent_credential_fail_closed_when_agent_down(tmp_path, store, monkeypatch):
    """Agent停止中でもローカル失効は完了し、sync_state=pending として記録される (fail-closed)。"""
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = _admin_headers()
    monkeypatch.setattr("httpx.post", _agent_down)
    with TestClient(app) as client:
        credential_id = _register_agent_credential(client, headers)
        response = client.post(f"/api/agent-credentials/{credential_id}/revoke", headers=headers)
        assert response.status_code == 202
        data = response.json()
        assert data["revoked"] is True
        assert data["agent_synced"] is False
        assert data["sync_state"] == "pending"
        assert "connection refused" in data["sync_detail"]
    credential = store.get_agent_credential(credential_id)
    assert credential.enabled is False
    assert credential.agent_sync_state == "pending"
    assert [c.id for c in store.list_pending_revocation_syncs()] == [credential_id]


def test_revoke_agent_credential_idempotent_when_agent_missing_token(tmp_path, store, monkeypatch):
    """Agentが404を返す場合 (既に失効済み/未登録) も同期成功として扱い、冪等に完了する。"""
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = _admin_headers()
    monkeypatch.setattr("httpx.post", lambda *args, **kwargs: type("Response", (), {"status_code": 404})())
    with TestClient(app) as client:
        credential_id = _register_agent_credential(client, headers)
        response = client.post(f"/api/agent-credentials/{credential_id}/revoke", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["revoked"] is True
        assert data["agent_synced"] is True
        assert data["sync_state"] == "synced"
    assert store.get_agent_credential(credential_id).agent_sync_state == "synced"
    assert store.list_pending_revocation_syncs() == []


def test_resync_pending_revocations_after_agent_recovery(tmp_path, store, monkeypatch):
    """Agent復旧後にresync-pendingで失効が再送され、pendingが解消される。"""
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = _admin_headers()
    monkeypatch.setattr("httpx.post", _agent_down)
    with TestClient(app) as client:
        credential_id = _register_agent_credential(client, headers)
        client.post(f"/api/agent-credentials/{credential_id}/revoke", headers=headers)
        assert store.get_agent_credential(credential_id).agent_sync_state == "pending"
        # Agent復旧
        monkeypatch.setattr("httpx.post", _agent_ok)
        response = client.post("/api/agent-credentials/resync-pending", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["remaining_pending"] == 0
        assert len(body["results"]) == 1
        result = body["results"][0]
        assert result["id"] == credential_id
        assert result["agent_token_id"] == "agent-1"
        assert result["synced"] is True
        assert result["sync_state"] == "synced"
    assert store.get_agent_credential(credential_id).agent_sync_state == "synced"
    assert store.list_pending_revocation_syncs() == []


def test_resync_pending_keeps_pending_on_failure(tmp_path, store, monkeypatch):
    """再送でもAgentが停止中ならpendingのまま維持される (fail-closedの継続)。"""
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = _admin_headers()
    monkeypatch.setattr("httpx.post", _agent_down)
    with TestClient(app) as client:
        credential_id = _register_agent_credential(client, headers)
        client.post(f"/api/agent-credentials/{credential_id}/revoke", headers=headers)
        response = client.post("/api/agent-credentials/resync-pending", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["remaining_pending"] == 1
        assert body["results"][0]["synced"] is False
        assert body["results"][0]["sync_state"] == "pending"
    assert store.get_agent_credential(credential_id).agent_sync_state == "pending"
    assert [c.id for c in store.list_pending_revocation_syncs()] == [credential_id]


def test_resync_single_agent_credential(tmp_path, store, monkeypatch):
    """単一credentialのresync: Agent停止中は502、復旧後はsyncedになる。"""
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = _admin_headers()
    monkeypatch.setattr("httpx.post", _agent_down)
    with TestClient(app) as client:
        credential_id = _register_agent_credential(client, headers)
        client.post(f"/api/agent-credentials/{credential_id}/revoke", headers=headers)
        # Agent停止中のresyncは502
        failed = client.post(f"/api/agent-credentials/{credential_id}/resync", headers=headers)
        assert failed.status_code == 502
        assert store.get_agent_credential(credential_id).agent_sync_state == "pending"
        # Agent復旧後のresyncは成功
        monkeypatch.setattr("httpx.post", _agent_ok)
        response = client.post(f"/api/agent-credentials/{credential_id}/resync", headers=headers)
        assert response.status_code == 200
        assert response.json()["sync_state"] == "synced"
    assert store.get_agent_credential(credential_id).agent_sync_state == "synced"


def test_resync_rejects_active_credential(tmp_path, store, monkeypatch):
    """失効していないcredentialへのresyncは409で拒否される。"""
    app = create_app(_config(tmp_path, username="admin", password="secret", admin_token="admin-secret"), store=store)
    headers = _admin_headers()
    monkeypatch.setattr("httpx.post", _agent_down)
    with TestClient(app) as client:
        credential_id = _register_agent_credential(client, headers)
        response = client.post(f"/api/agent-credentials/{credential_id}/resync", headers=headers)
        assert response.status_code == 409
