"""管理コンソール FastAPI アプリの組立て。"""

from __future__ import annotations

import base64
import logging
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
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
from .auth import current_principal, reset_current_principal, set_current_principal
from .approvals import ApprovalStore
from .config import AppConfig, load_config
from .db import TokenStore
from .mcp_audit import McpAudit
from .mcp_ratelimit import RateLimiter
from .oidc import OidcError, OidcValidator

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
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("Origin")
            if origin:
                origin_parts = urlsplit(origin)
                request_origin = f"{request.url.scheme}://{request.url.netloc}"
                if f"{origin_parts.scheme}://{origin_parts.netloc}" != request_origin:
                    return Response(status_code=403, content="Cross-origin mutation rejected")
        provided = request.headers.get("Authorization", "")
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
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("McpAudit 初期化に失敗 (監査ログを無効化): %s", exc)
        return None


def _maybe_rate_limit(app: FastAPI, config: AppConfig) -> None:
    """Add rate limiting middleware if enabled."""

    per_minute = config.console.rate_limit_per_minute
    burst = config.console.rate_limit_burst
    if per_minute <= 0 or burst <= 0:
        return
    limiter = RateLimiter(per_minute=per_minute, burst=burst)

    @app.middleware("http")
    async def _rate_limit(request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        if not limiter.allow(client_ip):
            return Response(
                status_code=429,
                content="429 Too Many Requests",
                headers={"Retry-After": "60"},
            )
        return await call_next(request)


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
    _maybe_basic_auth(app, config)
    _maybe_rate_limit(app, config)

    logger.info(
        "Linux Remote Management MCP Server v%s ready (servers=%d)", __version__, len(config.servers)
    )
    return app
