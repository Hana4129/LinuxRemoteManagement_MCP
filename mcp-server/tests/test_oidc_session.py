"""OIDC ブラウザログイン (Authorization Code + PKCE) とセッションCookieのテスト。"""

from __future__ import annotations

import sqlite3
import time
import urllib.parse

import httpx
import jwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig, load_config
from app.db import TokenStore
from console.main import create_app
from console.oidc_browser import _pkce_challenge

ISSUER = "https://issuer.example"
JWKS_URL = ISSUER + "/keys"
WELL_KNOWN = ISSUER + "/.well-known/openid-configuration"
AUTH_ENDPOINT = ISSUER + "/auth"
TOKEN_ENDPOINT = ISSUER + "/token"
REDIRECT_URI = "https://console.example/api/auth/callback"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KID = "test-key-1"
_JWK = dict(jwt.algorithms.RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key(), as_dict=True))
_JWK.update({"kid": _KID, "alg": "RS256", "use": "sig"})


def _config(tmp_path, **console_overrides) -> AppConfig:
    console: dict = {
        "data_dir": str(tmp_path),
        "auth_required": True,
        "auth_mode": "oidc",
        "oidc_issuer": ISSUER,
        "oidc_audience": "lrm",
        "oidc_jwks_url": JWKS_URL,
        "oidc_browser_login": True,
        "oidc_client_id": "lrm-console",
        "oidc_redirect_uri": REDIRECT_URI,
        "session_cookie_secure": False,
        "mcp_http": False,
    }
    console.update(console_overrides)
    return AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(ServerConfig(id="dev", name="Dev", url="http://127.0.0.1:1", env="development"),),
        agent=AgentConfig(timeout_seconds=2.0, tls_verify=False),
        console=ConsoleConfig(**console),
    )


def _mint_id_token(sub: str, nonce: str | None = None, **overrides) -> str:
    now = int(time.time())
    payload: dict = {"iss": ISSUER, "aud": "lrm", "sub": sub, "iat": now, "exp": now + 600}
    payload.update(overrides)
    if nonce is not None:
        payload["nonce"] = nonce
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256", headers={"kid": _KID})


def _response(url: str, body: dict, status_code: int = 200) -> httpx.Response:
    request = httpx.Request("GET", url)
    return httpx.Response(status_code, json=body, request=request)


def _install_fake_idp(monkeypatch, id_token_for, token_requests: list) -> None:
    """well-known / JWKS / token endpoint をローカルで模倣する。"""

    def fake_get(url, **kwargs):
        if url == WELL_KNOWN:
            return _response(url, {"authorization_endpoint": AUTH_ENDPOINT, "token_endpoint": TOKEN_ENDPOINT})
        if url == JWKS_URL:
            return _response(url, {"keys": [_JWK]})
        return _response(url, {}, status_code=404)

    def fake_post(url, data=None, auth=None, **kwargs):
        token_requests.append({"url": url, "data": data or {}, "auth": auth})
        if url != TOKEN_ENDPOINT:
            return _response(url, {}, status_code=404)
        return _response(url, {"id_token": id_token_for(data or {}), "token_type": "Bearer"})

    monkeypatch.setattr("httpx.get", fake_get)
    monkeypatch.setattr("httpx.post", fake_post)


def _login(client: TestClient) -> dict:
    """/api/auth/login を実行して認可URLのクエリパラメータを返す。"""
    response = client.get("/api/auth/login", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(AUTH_ENDPOINT)
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))


def _backdate_session(tmp_path, session_id: str) -> None:
    conn = sqlite3.connect(tmp_path / "sessions.db")
    conn.execute(
        "UPDATE browser_sessions SET expires_at='2000-01-01T00:00:00+00:00' WHERE session_id=?",
        (session_id,),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# テスト
# ---------------------------------------------------------------------------


def test_full_login_flow_with_pkce(tmp_path, store, monkeypatch):
    """login → callback → セッションCookie → CSRF強制 → API利用の一連のフロー。"""
    store.create_principal("browser-user", "Browser User", "admin")
    nonce_holder: dict = {}
    token_requests: list = []

    def id_token_for(data: dict) -> str:
        return _mint_id_token(sub="browser-user", nonce=nonce_holder.get("nonce"))

    _install_fake_idp(monkeypatch, id_token_for, token_requests)
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        params = _login(client)
        assert params["code_challenge_method"] == "S256"
        assert params["client_id"] == "lrm-console"
        assert params["redirect_uri"] == REDIRECT_URI
        nonce_holder["nonce"] = params["nonce"]

        callback = client.get(
            "/api/auth/callback",
            params={"code": "the-code", "state": params["state"]},
            follow_redirects=False,
        )
        assert callback.status_code == 302
        assert callback.headers["location"] == "/"

        # PKCE: token endpoint へ送られた verifier の S256 が challenge と一致
        assert len(token_requests) == 1
        verifier = token_requests[0]["data"]["code_verifier"]
        assert _pkce_challenge(verifier) == params["code_challenge"]

        # セッションCookieが発行されている
        assert client.cookies.get("lrm_session")

        me = client.get("/api/auth/me")
        assert me.status_code == 200
        body = me.json()
        assert body["authenticated"] is True
        assert body["subject"] == "browser-user"
        assert body["role"] == "admin"
        csrf = body["csrf_token"]

        # セッションでAPI利用可能
        assert client.get("/api/meta").status_code == 200

        # 変更系リクエストはCSRFトークン必須
        payload = {"subject": "new-user", "display_name": "New User", "role": "viewer"}
        assert client.post("/api/principals", json=payload).status_code == 403
        created = client.post("/api/principals", json=payload, headers={"X-CSRF-Token": csrf})
        assert created.status_code == 200


def test_callback_rejects_unknown_state(tmp_path, store, monkeypatch):
    store.create_principal("browser-user", "Browser User", "viewer")
    _install_fake_idp(monkeypatch, lambda data: _mint_id_token(sub="browser-user"), [])
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        response = client.get(
            "/api/auth/callback",
            params={"code": "the-code", "state": "bogus-state"},
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert client.cookies.get("lrm_session") is None


def test_login_state_is_single_use(tmp_path, store, monkeypatch):
    """同じ state の callback 再送 (リプレイ) は拒否される。"""
    store.create_principal("browser-user", "Browser User", "viewer")
    nonce_holder: dict = {}
    _install_fake_idp(
        monkeypatch,
        lambda data: _mint_id_token(sub="browser-user", nonce=nonce_holder.get("nonce")),
        [],
    )
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        params = _login(client)
        nonce_holder["nonce"] = params["nonce"]
        first = client.get(
            "/api/auth/callback",
            params={"code": "the-code", "state": params["state"]},
            follow_redirects=False,
        )
        assert first.status_code == 302
        replay = client.get(
            "/api/auth/callback",
            params={"code": "the-code", "state": params["state"]},
            follow_redirects=False,
        )
        assert replay.status_code == 400


def test_callback_rejects_nonce_mismatch(tmp_path, store, monkeypatch):
    """id_token の nonce が state に紐づくものと一致しない場合は拒否する。"""
    store.create_principal("browser-user", "Browser User", "viewer")
    _install_fake_idp(
        monkeypatch, lambda data: _mint_id_token(sub="browser-user", nonce="attacker-nonce"), []
    )
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        params = _login(client)
        callback = client.get(
            "/api/auth/callback",
            params={"code": "the-code", "state": params["state"]},
            follow_redirects=False,
        )
        assert callback.status_code == 401
        assert client.cookies.get("lrm_session") is None


def test_callback_rejects_unregistered_subject(tmp_path, store, monkeypatch):
    """未登録 subject のログインは403で拒否され、セッションは発行されない。"""
    nonce_holder: dict = {}
    _install_fake_idp(
        monkeypatch, lambda data: _mint_id_token(sub="stranger", nonce=nonce_holder.get("nonce")), []
    )
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        params = _login(client)
        nonce_holder["nonce"] = params["nonce"]
        callback = client.get(
            "/api/auth/callback",
            params={"code": "the-code", "state": params["state"]},
            follow_redirects=False,
        )
        assert callback.status_code == 403
        assert client.cookies.get("lrm_session") is None


def test_logout_invalidates_session(tmp_path, store, monkeypatch):
    store.create_principal("browser-user", "Browser User", "viewer")
    nonce_holder: dict = {}
    _install_fake_idp(
        monkeypatch,
        lambda data: _mint_id_token(sub="browser-user", nonce=nonce_holder.get("nonce")),
        [],
    )
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        params = _login(client)
        nonce_holder["nonce"] = params["nonce"]
        assert (
            client.get(
                "/api/auth/callback",
                params={"code": "c", "state": params["state"]},
                follow_redirects=False,
            ).status_code
            == 302
        )
        assert client.get("/api/auth/me").status_code == 200

        response = client.post("/api/auth/logout")
        assert response.status_code == 200
        assert response.json()["logged_out"] is True
        assert client.get("/api/auth/me").status_code == 401
        # 保護APIも未認証扱い (セッション消失後はOIDC Bearer必須の401)
        assert client.get("/api/meta").status_code == 401


def test_expired_and_forged_sessions_are_rejected(tmp_path, store, monkeypatch):
    store.create_principal("browser-user", "Browser User", "admin")
    nonce_holder: dict = {}
    _install_fake_idp(
        monkeypatch,
        lambda data: _mint_id_token(sub="browser-user", nonce=nonce_holder.get("nonce")),
        [],
    )
    app = create_app(_config(tmp_path), store=store)
    with TestClient(app) as client:
        params = _login(client)
        nonce_holder["nonce"] = params["nonce"]
        client.get(
            "/api/auth/callback",
            params={"code": "c", "state": params["state"]},
            follow_redirects=False,
        )
        session_id = client.cookies.get("lrm_session")
        assert session_id

        # forged cookie は未認証扱い
        forged = TestClient(app)
        forged.cookies.set("lrm_session", "forged-session-id")
        assert forged.get("/api/auth/me").status_code == 401

        # 期限切れセッションは401
        _backdate_session(tmp_path, session_id)
        assert client.get("/api/auth/me").status_code == 401


def test_browser_login_config_validation(tmp_path):
    """oidc_browser_login には client_id と https の redirect_uri が必要。"""
    base_console = {
        "auth_mode": "oidc",
        "oidc_issuer": ISSUER,
        "oidc_audience": "lrm",
        "oidc_jwks_url": JWKS_URL,
        "oidc_browser_login": True,
        "oidc_redirect_uri": REDIRECT_URI,
    }
    data = {
        "servers": [{"id": "dev", "name": "Dev", "url": "http://127.0.0.1:1", "env": "development"}],
        "console": dict(base_console),
    }
    missing_client = tmp_path / "missing_client.yml"
    missing_client.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(missing_client)

    http_redirect = dict(base_console, oidc_client_id="lrm-console", oidc_redirect_uri="http://console.example/api/auth/callback")
    insecure = tmp_path / "insecure.yml"
    insecure.write_text(yaml.safe_dump({"servers": data["servers"], "console": http_redirect}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(insecure)

    valid = dict(base_console, oidc_client_id="lrm-console")
    ok = tmp_path / "valid.yml"
    ok.write_text(yaml.safe_dump({"servers": data["servers"], "console": valid}), encoding="utf-8")
    config = load_config(ok)
    assert config.console.oidc_browser_login is True
    assert config.console.session_lifetime_minutes == 480
