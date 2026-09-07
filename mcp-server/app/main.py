"""管理コンソール FastAPI アプリの組立て。"""

from __future__ import annotations

import base64
import logging
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .api import (
    agent_credentials_router,
    approvals_router,
    meta_router,
    nodes_router,
    principals_router,
    servers_router,
    tokens_router,
)
from .auth import authenticate_raw_token, current_principal, reset_current_principal, set_current_principal
from .approvals import ApprovalStore
from .config import AppConfig, load_config
from .db import TokenStore
from .mcp_audit import McpAudit
from .mcp_ratelimit import install_rate_limit
from .oidc import OidcError, OidcValidator
from .oidc_browser import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    BrowserSessionStore,
    OidcBrowserError,
    build_authorization_url,
    exchange_code,
    _pkce_challenge,
)

logger = logging.getLogger("linux_mcp")

BASE_DIR = Path(__file__).resolve().parent.parent


def _maybe_basic_auth(app: FastAPI, config: AppConfig) -> None:
    if not config.console.auth_required:
        return
    if config.console.auth_mode == "oidc":
        validator = OidcValidator(
            config.console.oidc_issuer,
            config.console.oidc_audience,
            config.console.oidc_jwks_url,
        )

        @app.middleware("http")
        async def _oidc_auth(request: Request, call_next):
            if current_principal() is not None:
                # セッション認証 (ブラウザログイン) 済みのため何もしない
                return await call_next(request)
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return Response(status_code=401, content="OIDC Bearer token required")
            try:
                claims = validator.validate(header[7:].strip())
            except OidcError:
                return Response(status_code=401, content="Invalid OIDC token")
            principal = request.app.state.store.get_principal_by_subject(str(claims["sub"]))
            if principal is None:
                return Response(status_code=403, content="OIDC subject is not provisioned")
            context = set_current_principal(principal)
            try:
                request.state.principal = principal
                return await call_next(request)
            finally:
                reset_current_principal(context)
        return
    if not (config.console.username and config.console.password):
        raise ValueError("console.auth_required=true ですが username/password が未設定です")
    expected = "Basic " + base64.b64encode(
        f"{config.console.username}:{config.console.password}".encode("utf-8")
    ).decode("ascii")

    @app.middleware("http")
    async def _basic_auth(request: Request, call_next):
        # Bearerトークンの場合はMCPトークン認証 (_maybe_mcp_token_auth) に任せる
        provided = request.headers.get("Authorization", "")
        if provided.startswith("Bearer "):
            return await call_next(request)

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("Origin")
            if origin:
                origin_parts = urlsplit(origin)
                request_origin = f"{request.url.scheme}://{request.url.netloc}"
                if f"{origin_parts.scheme}://{origin_parts.netloc}" != request_origin:
                    return Response(status_code=403, content="Cross-origin mutation rejected")
        if not secrets.compare_digest(provided, expected):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="linux-mcp-console"'},
                content="401 Unauthorized",
            )
        principal_context = set_current_principal(
            {
                "id": "basic-admin",
                "subject": config.console.username,
                "display_name": config.console.username,
                "role": "admin",
                "enabled": 1,
                "auth_method": "basic",
            }
        )
        try:
            request.state.principal = current_principal()
            return await call_next(request)
        finally:
            reset_current_principal(principal_context)


def _maybe_mcp_token_auth(app: FastAPI, config: AppConfig) -> None:
    """MCP Bearer トークンを検証し、紐づく principal を設定するミドルウェア。

    Basic/OIDC 認証ミドルウェアの内側で動作し、そこで処理されなかった
    Bearer トークンを MCP credential として認証する。
    無効なトークンや principal に紐づかないトークンは 401 で拒否する。
    """

    @app.middleware("http")
    async def _mcp_token_auth(request: Request, call_next):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return await call_next(request)
        if current_principal() is not None:
            # Basic/OIDC ミドルウェアで認証済みのため何もしない
            return await call_next(request)
        store = getattr(request.app.state, "store", None)
        if store is None:
            return await call_next(request)
        token = authenticate_raw_token(store, header[7:].strip())
        if token is None or not token.principal_id:
            return Response(status_code=401, content="Invalid or unlinked MCP token")
        principal = store.get_principal(token.principal_id)
        if principal is None:
            return Response(status_code=401, content="Invalid or unlinked MCP token")
        context = set_current_principal(principal)
        try:
            request.state.principal = principal
            return await call_next(request)
        finally:
            reset_current_principal(context)


def _maybe_oidc_session(app: FastAPI, config: AppConfig) -> None:
    """OIDC Authorization Code + PKCE ブラウザログインとセッションCookie認証を有効化する。

    Basic/OIDC Bearer 認証より外側で動作し、有効なセッションCookieがあれば
    principal を設定して以降のミドルウェア・APIを通過させる。
    変更系リクエストには X-CSRF-Token ヘッダーを要求する。
    """
    console = config.console
    if not console.auth_required or console.auth_mode != "oidc" or not console.oidc_browser_login:
        return
    sessions = BrowserSessionStore(config.data_dir / "sessions.db")
    max_age = console.session_lifetime_minutes * 60
    cookie_secure = console.session_cookie_secure

    def _set_session_cookies(response: Response, session: dict) -> None:
        response.set_cookie(
            SESSION_COOKIE, session["session_id"], max_age=max_age,
            httponly=True, samesite="lax", secure=cookie_secure, path="/",
        )
        # CSRFトークンはJSから読めるよう non-HttpOnly で発行する (機密値ではない)
        response.set_cookie(
            CSRF_COOKIE, session["csrf_token"], max_age=max_age,
            httponly=False, samesite="strict", secure=cookie_secure, path="/",
        )

    @app.middleware("http")
    async def _oidc_session(request: Request, call_next):
        path = request.url.path
        method = request.method
        store: TokenStore = request.app.state.store

        if path == "/api/auth/login" and method == "GET":
            state, verifier, nonce = sessions.create_login_state()
            try:
                url = build_authorization_url(console, state, _pkce_challenge(verifier), nonce)
            except OidcBrowserError as exc:
                return JSONResponse({"detail": str(exc)}, status_code=503)
            return RedirectResponse(url, status_code=302)

        if path == "/api/auth/callback" and method == "GET":
            error = request.query_params.get("error")
            if error:
                detail = request.query_params.get("error_description") or error
                return JSONResponse({"detail": f"IdPがログインを拒否しました: {detail}"}, status_code=400)
            state = request.query_params.get("state", "")
            code = request.query_params.get("code", "")
            state_data = sessions.pop_login_state(state) if state else None
            if state_data is None:
                return JSONResponse({"detail": "state が無効または期限切れです"}, status_code=400)
            try:
                id_token = exchange_code(console, code, state_data["code_verifier"])
                claims = OidcValidator(
                    console.oidc_issuer, console.oidc_audience, console.oidc_jwks_url
                ).validate(id_token)
            except (OidcBrowserError, OidcError) as exc:
                return JSONResponse({"detail": f"OIDCログインに失敗しました: {exc}"}, status_code=401)
            if claims.get("nonce") != state_data["nonce"]:
                return JSONResponse({"detail": "nonce が一致しません"}, status_code=401)
            subject = str(claims.get("sub") or "")
            principal = store.get_principal_by_subject(subject)
            if principal is None:
                return JSONResponse({"detail": f"未登録のsubjectです: {subject}"}, status_code=403)
            session = sessions.create_session(principal, console.session_lifetime_minutes)
            response = RedirectResponse("/", status_code=302)
            _set_session_cookies(response, session)
            return response

        if path == "/api/auth/logout" and method == "POST":
            sessions.delete_session(request.cookies.get(SESSION_COOKIE, ""))
            response = JSONResponse({"logged_out": True})
            response.delete_cookie(SESSION_COOKIE, path="/")
            response.delete_cookie(CSRF_COOKIE, path="/")
            return response

        if path == "/api/auth/me" and method == "GET":
            session = sessions.get_session(request.cookies.get(SESSION_COOKIE, ""))
            if session is None:
                return JSONResponse({"authenticated": False}, status_code=401)
            return JSONResponse({
                "authenticated": True,
                "subject": session["subject"],
                "display_name": session["display_name"],
                "role": session["role"],
                "csrf_token": session["csrf_token"],
                "expires_at": session["expires_at"],
            })

        sid = request.cookies.get(SESSION_COOKIE, "")
        if not sid:
            return await call_next(request)
        session = sessions.get_session(sid)
        if session is None:
            # 無効・期限切れのcookieは無視して未認証扱い (保護APIは401を返す)
            return await call_next(request)
        if method in {"POST", "PUT", "DELETE", "PATCH"} and not path.startswith("/api/auth/"):
            header_token = request.headers.get("X-CSRF-Token", "")
            if not header_token or not secrets.compare_digest(header_token, session["csrf_token"]):
                return JSONResponse({"detail": "CSRF token が無効です"}, status_code=403)
        principal = store.get_principal(session["principal_id"])
        if principal is None or not principal.get("enabled", True):
            sessions.delete_session(sid)
            return JSONResponse({"detail": "セッションの principal が無効です"}, status_code=401)
        context = set_current_principal(principal)
        try:
            request.state.principal = principal
            request.state.session_auth = True
            return await call_next(request)
        finally:
            reset_current_principal(context)


def _maybe_approval_store(config: AppConfig) -> ApprovalStore | None:
    if not config.console.require_approval:
        return None
    try:
        return ApprovalStore(config.data_dir / "approvals.db")
    except Exception as exc:  # noqa: BLE001
        logger.warning("ApprovalStore 初期化に失敗 (承認機能を無効化): %s", exc)
        return None


def _maybe_audit(config: AppConfig) -> McpAudit | None:
    if not config.console.mcp_audit:
        return None
    try:
        return McpAudit(
            config.data_dir / "mcp_audit.log",
            max_size_mb=config.console.audit_max_size_mb,
            max_backups=config.console.audit_max_backups,
            compress=config.console.audit_compress,
            siem_webhook=config.console.siem_webhook,
            siem_api_key=config.console.siem_api_key,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("McpAudit 初期化に失敗 (監査ログを無効化): %s", exc)
        return None


def _maybe_rate_limit(app: FastAPI, config: AppConfig) -> None:
    """Add rate limiting middleware if enabled (IP + token composite, read/write separated)."""

    install_rate_limit(
        app,
        per_minute=config.console.rate_limit_per_minute,
        burst=config.console.rate_limit_burst,
        write_per_minute=config.console.rate_limit_write_per_minute,
        write_burst=config.console.rate_limit_write_burst,
        token_per_minute=config.console.rate_limit_token_per_minute,
        token_burst=config.console.rate_limit_token_burst,
    )


def create_app(config: AppConfig | None = None, store: TokenStore | None = None) -> FastAPI:
    """管理コンソール + MCP マウントを含む FastAPI アプリを構築する。"""
    config = config or load_config()
    store = store or TokenStore(config.data_dir / "tokens.db")
    approvals = _maybe_approval_store(config)
    audit = _maybe_audit(config)

    app = FastAPI(title="Linux Remote Management Console", version=__version__)
    app.state.config = config
    app.state.store = store
    app.state.approvals = approvals
    app.state.audit = audit
    app.state.mcp_http_enabled = False

    app.include_router(meta_router)
    app.include_router(nodes_router)
    app.include_router(tokens_router)
    app.include_router(principals_router)
    app.include_router(agent_credentials_router)
    app.include_router(servers_router)
    # 承認APIは require_approval=False でも常設する (無効時は各エンドポイントが503を返す)
    app.include_router(approvals_router)

    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"version": __version__, "mcp_http_enabled": app.state.mcp_http_enabled},
        )

    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
    # MCP Bearer トークン認証は Basic/OIDC の内側 (最後に実行) で登録し、
    # 未処理の Bearer トークンを引き取らせる
    _maybe_mcp_token_auth(app, config)
    _maybe_basic_auth(app, config)
    _maybe_oidc_session(app, config)
    _maybe_rate_limit(app, config)

    logger.info(
        "Linux Remote Management MCP Server v%s ready (servers=%d)", __version__, len(config.servers)
    )
    return app
