"""P2-12 テスト拡張: 管理操作マトリクス・権限分離・並行制御・DB互換・OIDC実JWT/JWKSテスト."""
from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from app.agent_client import AgentClient
from console.auth import reset_current_token, set_current_token
from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig
from app.db import TokenStore
from console.main import create_app

# ---------------------------------------------------------------------------
# ヘルパー
# ---------------------------------------------------------------------------


def _config(tmp_path: Path, *, username: str = "admin", password: str = "secret") -> AppConfig:
    return AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(
            ServerConfig(id="dev", name="Dev", url="http://127.0.0.1:1"),
            ServerConfig(id="srv-a", name="Server A", url="http://127.0.0.1:2"),
            ServerConfig(id="srv-b", name="Server B", url="http://127.0.0.1:3"),
        ),
        agent=AgentConfig(timeout_seconds=1, tls_verify=False),
        console=ConsoleConfig(
            data_dir=str(tmp_path),
            username=username,
            password=password,
            auth_required=True,
            mcp_http=False,
        ),
    )


def _admin_headers() -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode("ascii")}


def _principal_token(client: TestClient, subject: str, role: str, scope: str) -> tuple[str, str]:
    """principal と紐付け MCP トークンを作成し、(principal_id, 生トークン) を返す。"""
    admin = _admin_headers()
    principal = client.post(
        "/api/principals",
        json={"subject": subject, "display_name": subject, "role": role},
        headers=admin,
    )
    assert principal.status_code == 200, principal.text
    principal_id = principal.json()["id"]
    token = client.post(
        "/api/tokens",
        json={"name": f"{subject}-token", "principal_id": principal_id, "server_ids": ["*"], "scope": scope},
        headers=admin,
    )
    assert token.status_code == 200, token.text
    return principal_id, token.json()["token"]


# ---------------------------------------------------------------------------
# 1. admin/operator/viewer 管理操作マトリクス
# ---------------------------------------------------------------------------


def _management_matrix_case(client: TestClient, role: str) -> list[tuple[str, int]]:
    """ロール別に管理操作を実行し、(操作名, ステータスコード) を返す。"""
    if role == "admin":
        _, token = _principal_token(client, "matrix-admin", "admin", "operator")
    elif role == "viewer":
        _, token = _principal_token(client, f"matrix-{role}", role, "readonly")
    else:
        _, token = _principal_token(client, f"matrix-{role}", role, "operator")
    headers = {"Authorization": f"Bearer {token}"}

    create_status = client.post(
        "/api/principals",
        json={"subject": "matrix-target", "display_name": "Target", "role": "viewer"},
        headers=headers,
    ).status_code

    target_id = client.post(
        "/api/principals",
        json={"subject": "matrix-grant-target", "display_name": "Grant Target", "role": "viewer"},
        headers=_admin_headers(),
    ).json()["id"]
    grant_status = client.post(
        f"/api/principals/{target_id}/permissions",
        json={"server_id": "dev", "scope": "readonly"},
        headers=headers,
    ).status_code

    revoke_status = client.delete(
        f"/api/principals/{target_id}/permissions/readonly/dev",
        headers=headers,
    ).status_code

    disable_status = client.post(
        f"/api/principals/{target_id}/disable",
        headers=headers,
    ).status_code

    return [
        ("create_principal", create_status),
        ("grant_permission", grant_status),
        ("revoke_permission", revoke_status),
        ("disable_principal", disable_status),
    ]


@pytest.mark.parametrize("role,allowed", [("admin", True), ("operator", False), ("viewer", False)])
def test_management_operation_matrix(tmp_path, store, role, allowed):
    """admin/operator/viewer ロールの管理操作許可マトリクスを検証する。

    admin ロールのみ管理操作が許可され、operator/viewer は全操作が 403 になる。
    """
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        results = _management_matrix_case(client, role)
    for operation, status in results:
        if allowed:
            assert status == 200, f"admin ロールの {operation} は 200 のはず (実際: {status})"
        else:
            assert status == 403, f"{role} ロールの {operation} は 403 のはず (実際: {status})"


def test_basic_auth_admin_can_perform_all_management_operations(tmp_path, store):
    """Basic認証 (admin) は全管理操作が許可される。"""
    app = create_app(_config(tmp_path), store=store)
    headers = _admin_headers()
    with TestClient(app) as client:
        principal_id = client.post(
            "/api/principals",
            json={"subject": "basic-target", "display_name": "Target", "role": "viewer"},
            headers=headers,
        ).json()["id"]
        assert client.post(
            f"/api/principals/{principal_id}/permissions",
            json={"server_id": "dev", "scope": "readonly"},
            headers=headers,
        ).status_code == 200
        assert client.delete(
            f"/api/principals/{principal_id}/permissions/readonly/dev",
            headers=headers,
        ).status_code == 200
        assert client.post(f"/api/principals/{principal_id}/disable", headers=headers).json()["disabled"] is True


# ---------------------------------------------------------------------------
# 2. principal A/B の server 権限分離
# ---------------------------------------------------------------------------


def test_principal_server_permission_separation(tmp_path, store):
    """principal A は許可されたサーバーのみアクセスでき、B のサーバーにはアクセスできない。"""
    import asyncio

    config = _config(tmp_path)
    store.create_principal("alice", "Alice", "viewer")
    store.create_principal("bob", "Bob", "viewer")
    alice = store.get_principal_by_subject("alice")
    bob = store.get_principal_by_subject("bob")
    assert alice and bob

    # トークンは server_ids=["*"] で作成し、実効権限は permission grant で分離する
    rec_a, _raw_a = store.create_token(
        name="alice-token", server_ids=["*"], scope="readonly", principal_id=alice["id"]
    )
    rec_b, _raw_b = store.create_token(
        name="bob-token", server_ids=["*"], scope="readonly", principal_id=bob["id"]
    )
    store.grant_permission(alice["id"], "srv-a", "readonly")
    store.grant_permission(bob["id"], "srv-b", "readonly")

    agent = AgentClient(config, store)
    try:
        ctx = set_current_token(rec_a)
        try:
            assert agent._token_for("srv-a") is rec_a, "alice は srv-a にアクセスできる"
            assert agent._token_for("srv-b") is None, "alice は srv-b にアクセスできない"
        finally:
            reset_current_token(ctx)

        ctx = set_current_token(rec_b)
        try:
            assert agent._token_for("srv-b") is rec_b, "bob は srv-b にアクセスできる"
            assert agent._token_for("srv-a") is None, "bob は srv-a にアクセスできない"
        finally:
            reset_current_token(ctx)

        # 権限失効後は自分のサーバーにもアクセスできない
        store.revoke_permission(alice["id"], "srv-a", "readonly")
        ctx = set_current_token(rec_a)
        try:
            assert agent._token_for("srv-a") is None, "失効後の alice は srv-a にアクセスできない"
        finally:
            reset_current_token(ctx)
    finally:
        asyncio.new_event_loop().run_until_complete(agent.aclose())



# ---------------------------------------------------------------------------
# 3. 並行した grant/revoke と token 認証
# ---------------------------------------------------------------------------


def test_concurrent_grant_revoke_and_token_auth(tmp_path, store):
    """grant/revoke とトークン認証を並行実行しても認証結果が破綻しない。"""
    store.create_principal("concurrent-user", "Concurrent", "viewer")
    principal = store.get_principal_by_subject("concurrent-user")
    assert principal
    rec, raw = store.create_token(
        name="concurrent-token", server_ids=["*"], scope="readonly", principal_id=principal["id"]
    )

    stop = threading.Event()
    errors: list[str] = []

    def grant_revoke_loop() -> None:
        try:
            while not stop.is_set():
                store.grant_permission(principal["id"], "srv-a", "readonly")
                store.revoke_permission(principal["id"], "srv-a", "readonly")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"grant/revoke: {exc!r}")

    def auth_loop() -> None:
        try:
            while not stop.is_set():
                token = store.get_by_raw(raw)
                if token is None or not token.active:
                    errors.append("トークンが無効化された (認証が破綻)")
                    return
                store.touch_last_used(rec.id)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"auth: {exc!r}")

    threads = [
        threading.Thread(target=grant_revoke_loop) for _ in range(2)
    ] + [threading.Thread(target=auth_loop) for _ in range(3)]
    for thread in threads:
        thread.start()
    time.sleep(1.0)
    stop.set()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive(), "スレッドが停止しない"

    assert not errors, f"並行実行中にエラー: {errors}"
    # 最終状態でもトークン認証は機能する
    assert store.get_by_raw(raw) is not None and store.get_by_raw(raw).active



# ---------------------------------------------------------------------------
# 4. SQLite migration の既存DB互換
# ---------------------------------------------------------------------------


_LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    prefix      TEXT NOT NULL,
    server_ids  TEXT NOT NULL,
    scope       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    last_used_at TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    token_raw   TEXT NOT NULL DEFAULT '',
    created_by  TEXT
);
CREATE TABLE IF NOT EXISTS agent_credentials (
    id          TEXT PRIMARY KEY,
    server_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    token_raw   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1
);
"""


def test_migration_from_legacy_db(tmp_path, store):
    """旧スキーマ (新カラム無し) のDBを開いても migration され、既存行が保持される。"""
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_LEGACY_SCHEMA)
    conn.execute(
        "INSERT INTO tokens (id, name, token_hash, prefix, server_ids, scope, created_at, enabled, token_raw) "
        "VALUES ('legacy-tok', 'legacy', 'abc', 'lrma_abcd', '[\"dev\"]', 'readonly', '2020-01-01T00:00:00+00:00', 1, 'raw')"
    )
    conn.execute(
        "INSERT INTO agent_credentials (id, server_id, name, token_raw, created_at, enabled) "
        "VALUES ('legacy-cred', 'dev', 'legacy-agent', 'raw', '2020-01-01T00:00:00+00:00', 1)"
    )
    conn.commit()
    conn.close()

    # TokenStore を開くと migration が走る
    migrated = TokenStore(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        token_columns = {row["name"] for row in conn.execute("PRAGMA table_info(tokens)")}
        credential_columns = {row["name"] for row in conn.execute("PRAGMA table_info(agent_credentials)")}
    assert {"rotated_from", "grace_ends_at", "principal_id"} <= token_columns
    assert {"agent_token_id", "agent_sync_state", "grace_ends_at"} <= credential_columns

    # 旧行が保持されている
    legacy_token = migrated.get_token("legacy-tok")
    assert legacy_token is not None and legacy_token.enabled
    legacy_credential = migrated.get_agent_credential("legacy-cred")
    assert legacy_credential is not None and legacy_credential.enabled
    assert legacy_credential.agent_sync_state == "synced"

    # migration 後も新機能 (principal紐付けトークン・ローテーション) が動作する
    store.create_principal("post-migration", "Post", "viewer")
    principal = store.get_principal_by_subject("post-migration")
    assert principal
    record, raw = store.create_token(
        name="new-token", server_ids=["dev"], scope="readonly", principal_id=principal["id"]
    )
    assert store.get_by_raw(raw) is not None
    rotated = store.rotate_token(record.id, grace_period_days=1)
    assert rotated.rotated_from == record.id

    credential = migrated.create_agent_credential("dev", "new-agent", "secret", agent_token_id="agt-1")
    assert credential.agent_token_id == "agt-1"
    assert migrated.find_agent_credential("dev") is not None



# ---------------------------------------------------------------------------
# 5. OIDC 実JWT + JWKS 統合テスト
# ---------------------------------------------------------------------------

_ISSUER = "https://issuer.example"
_AUDIENCE = "lrm"
_KID = "test-key-1"
_NOW = int(time.time())


def _generate_key_and_jwks() -> tuple[bytes, dict]:
    """RSA鍵ペアと対応するJWKSを生成する。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": _KID, "alg": "RS256", "use": "sig"})
    return private_pem, {"keys": [jwk]}


def _make_jwt(private_pem: bytes, claims: dict, *, kid: str = _KID) -> str:
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


def _oidc_app(tmp_path, store, jwks: dict, monkeypatch):
    """実 OidcValidator を使うアプリを構築する (JWKS取得のみモック)。"""

    class _FakeJwksResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return jwks

    monkeypatch.setattr("console.oidc.httpx.get", lambda url, timeout: _FakeJwksResponse())
    config = AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(),
        agent=AgentConfig(timeout_seconds=1, tls_verify=False),
        console=ConsoleConfig(
            data_dir=str(tmp_path),
            auth_required=True,
            auth_mode="oidc",
            oidc_issuer=_ISSUER,
            oidc_audience=_AUDIENCE,
            oidc_jwks_url="https://issuer.example/keys",
            mcp_http=False,
        ),
    )
    return create_app(config, store=store)


def _claims(sub: str, *, aud: str = _AUDIENCE, exp_offset: int = 300) -> dict:
    return {"sub": sub, "iss": _ISSUER, "aud": aud, "exp": _NOW + exp_offset, "iat": _NOW}


def test_oidc_real_jwt_valid_and_provisioned(tmp_path, store, monkeypatch):
    """実署名つきRS256 JWTで登録済みsubjectがログインできる。"""
    private_pem, jwks = _generate_key_and_jwks()
    app = _oidc_app(tmp_path, store, jwks, monkeypatch)
    store.create_principal("alice", "Alice", "viewer")
    token = _make_jwt(private_pem, _claims("alice"))
    with TestClient(app) as client:
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text


def test_oidc_real_jwt_unprovisioned_subject_403(tmp_path, store, monkeypatch):
    """実署名つきJWTでも未登録subjectは403。"""
    private_pem, jwks = _generate_key_and_jwks()
    app = _oidc_app(tmp_path, store, jwks, monkeypatch)
    token = _make_jwt(private_pem, _claims("unknown"))
    with TestClient(app) as client:
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403



def test_oidc_real_jwt_tampered_signature_401(tmp_path, store, monkeypatch):
    """署名を改竄したJWTは401。"""
    private_pem, jwks = _generate_key_and_jwks()
    app = _oidc_app(tmp_path, store, jwks, monkeypatch)
    store.create_principal("alice", "Alice", "viewer")
    token = _make_jwt(private_pem, _claims("alice"))
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}.AAAA{signature[4:]}"
    with TestClient(app) as client:
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {tampered}"})
    assert response.status_code == 401


def test_oidc_real_jwt_expired_401(tmp_path, store, monkeypatch):
    """期限切れJWTは401。"""
    private_pem, jwks = _generate_key_and_jwks()
    app = _oidc_app(tmp_path, store, jwks, monkeypatch)
    store.create_principal("alice", "Alice", "viewer")
    token = _make_jwt(private_pem, _claims("alice", exp_offset=-10))
    with TestClient(app) as client:
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_oidc_real_jwt_wrong_audience_401(tmp_path, store, monkeypatch):
    """audience不一致のJWTは401。"""
    private_pem, jwks = _generate_key_and_jwks()
    app = _oidc_app(tmp_path, store, jwks, monkeypatch)
    store.create_principal("alice", "Alice", "viewer")
    token = _make_jwt(private_pem, _claims("alice", aud="other-client"))
    with TestClient(app) as client:
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_oidc_real_jwt_unknown_kid_401(tmp_path, store, monkeypatch):
    """JWKSに存在しないkidのJWTは401。"""
    private_pem, jwks = _generate_key_and_jwks()
    app = _oidc_app(tmp_path, store, jwks, monkeypatch)
    store.create_principal("alice", "Alice", "viewer")
    token = _make_jwt(private_pem, _claims("alice"), kid="rotated-away-key")
    with TestClient(app) as client:
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401



def test_oidc_key_rotation_picks_up_new_jwks(tmp_path, store, monkeypatch):
    """JWKS更新 (kid追加) 後の新鍵署名JWTで検証が成功する (キャッシュ無効化)。"""
    old_pem, jwks = _generate_key_and_jwks()
    app = _oidc_app(tmp_path, store, jwks, monkeypatch)
    store.create_principal("alice", "Alice", "viewer")

    # 旧鍵で一度検証して JWKS キャッシュを作る
    old_token = _make_jwt(old_pem, _claims("alice"))
    with TestClient(app) as client:
        assert client.get("/api/meta", headers={"Authorization": f"Bearer {old_token}"}).status_code == 200

        # 新しい鍵へローテーション: 新kidのJWKをJWKSへ追加
        new_pem, _ = _generate_key_and_jwks()
        new_key = serialization.load_pem_private_key(new_pem, password=None)
        new_jwk = json.loads(RSAAlgorithm.to_jwk(new_key.public_key()))
        new_jwk.update({"kid": "new-key", "alg": "RS256", "use": "sig"})
        jwks["keys"].append(new_jwk)

        new_token = _make_jwt(new_pem, _claims("alice"), kid="new-key")
        response = client.get("/api/meta", headers={"Authorization": f"Bearer {new_token}"})
    assert response.status_code == 200, response.text

