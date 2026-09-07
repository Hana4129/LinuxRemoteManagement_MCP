"""OIDC Authorization Code + PKCE ブラウザログインとセッション管理。

- セッションは SQLite (data_dir/sessions.db) に保存する
- セッションID / CSRFトークン / state / PKCE verifier はすべて CSPRNG 生成
- ログインstateは単回利用・10分TTL (リプレイ対策)
- CSRFはセッション紐付けトークン (X-CSRF-Token header) で強制する
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlencode

import httpx

from app.tokens import is_expired

SESSION_COOKIE = "lrm_session"
CSRF_COOKIE = "lrm_csrf"
LOGIN_STATE_TTL_SECONDS = 600


class OidcBrowserError(Exception):
    """OIDC ブラウザログインフローの失敗を表す。"""


def _iso_in(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# Discovery / トークン交換
# ---------------------------------------------------------------------------

_discovery_cache: dict[str, dict[str, Any]] = {}


def _discover(issuer: str) -> dict[str, Any]:
    cached = _discovery_cache.get(issuer)
    if cached is not None:
        return cached
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    response = httpx.get(url, timeout=5.0)
    response.raise_for_status()
    doc = response.json()
    _discovery_cache[issuer] = doc
    return doc


def _oidc_endpoint(console: Any, name: str) -> str:
    """name は 'authorization' または 'token'。設定値を優先し、なければ discovery で解決する。"""
    direct = getattr(console, f"oidc_{name}_endpoint", "")
    if direct:
        return direct
    doc = _discover(console.oidc_issuer)
    endpoint = doc.get(f"{name}_endpoint")
    if not endpoint:
        raise OidcBrowserError(f"OIDC discovery に {name}_endpoint がありません")
    return str(endpoint)


def build_authorization_url(console: Any, state: str, code_challenge: str, nonce: str) -> str:
    params = {
        "response_type": "code",
        "client_id": console.oidc_client_id,
        "redirect_uri": console.oidc_redirect_uri,
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return _oidc_endpoint(console, "authorization") + "?" + urlencode(params)


def exchange_code(console: Any, code: str, code_verifier: str) -> str:
    """認可コードをトークンエンドポイントと交換し id_token を返す。"""
    endpoint = _oidc_endpoint(console, "token")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": console.oidc_redirect_uri,
        "client_id": console.oidc_client_id,
        "code_verifier": code_verifier,
    }
    auth = (console.oidc_client_id, console.oidc_client_secret) if console.oidc_client_secret else None
    try:
        response = httpx.post(endpoint, data=data, auth=auth, timeout=10.0)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
        raise OidcBrowserError(f"トークンエンドポイントとの交換に失敗しました: {exc}") from exc
    id_token = payload.get("id_token")
    if not id_token:
        raise OidcBrowserError("トークンエンドポイントの応答に id_token がありません")
    return str(id_token)


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS browser_sessions (
    session_id   TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    subject      TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role         TEXT NOT NULL,
    csrf_token   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oidc_login_states (
    state         TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);
"""


class BrowserSessionStore:
    """ブラウザセッションとOIDCログインstateのSQLiteストア。"""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # -- ログインstate (単回利用・10分TTL) --

    def create_login_state(self) -> tuple[str, str, str]:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        nonce = secrets.token_urlsafe(16)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO oidc_login_states (state, code_verifier, nonce, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (state, verifier, nonce, _iso_in(0), _iso_in(LOGIN_STATE_TTL_SECONDS)),
            )
        return state, verifier, nonce

    def pop_login_state(self, state: str) -> dict[str, Any] | None:
        """state を取り出して削除する (単回利用)。未知・期限切れの state は None。"""
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM oidc_login_states WHERE state=?", (state,)).fetchone()
            conn.execute("DELETE FROM oidc_login_states WHERE state=?", (state,))
        if row is None:
            return None
        if is_expired(row["expires_at"]):
            return None
        return {"code_verifier": row["code_verifier"], "nonce": row["nonce"]}

    # -- セッション --

    def create_session(self, principal: dict[str, Any], lifetime_minutes: int) -> dict[str, Any]:
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        expires_at = _iso_in(lifetime_minutes * 60)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO browser_sessions (session_id, principal_id, subject, display_name, role, csrf_token, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    str(principal["id"]),
                    str(principal.get("subject", "")),
                    str(principal.get("display_name", "")),
                    str(principal.get("role", "")),
                    csrf_token,
                    _iso_in(0),
                    expires_at,
                ),
            )
        return {"session_id": session_id, "csrf_token": csrf_token, "expires_at": expires_at}

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        if not session_id:
            return None
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM browser_sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            return None
        session = dict(row)
        if is_expired(session.get("expires_at")):
            self.delete_session(session_id)
            return None
        return session

    def delete_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM browser_sessions WHERE session_id=?", (session_id,))
            return cur.rowcount > 0

    def purge_expired(self) -> int:
        """期限切れセッション・stateを掃除する (保守用)。"""
        removed = 0
        with self._lock, self._connect() as conn:
            for table in ("browser_sessions", "oidc_login_states"):
                cur = conn.execute(f"DELETE FROM {table} WHERE expires_at < ?", (_iso_in(0),))
                removed += cur.rowcount
        return removed
