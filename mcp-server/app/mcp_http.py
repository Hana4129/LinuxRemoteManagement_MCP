"""MCP streamable HTTP専用アプリ。管理コンソールとは別プロセスで起動する。"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from .auth import authenticate_raw_token, reset_current_token, set_current_token
from .config import AppConfig
from .db import TokenStore
from .mcp_audit import McpAudit
from .approvals import ApprovalStore
from .mcp_ratelimit import install_rate_limit
from .mcp_server import build_mcp
from .session_manager import get_session_manager


def create_mcp_http_app(config: AppConfig, store: TokenStore | None = None) -> FastAPI:
    store = store or TokenStore(config.data_dir / "tokens.db")
    approvals = ApprovalStore(config.data_dir / "approvals.db") if config.console.require_approval else None
    audit = McpAudit(config.data_dir / "mcp_audit.log") if config.console.mcp_audit else None
    mcp = build_mcp(config, store, approvals=approvals, audit=audit)

    # セッション管理マネージャー初期化
    session_manager = get_session_manager(
        session_timeout_minutes=getattr(config.console, "session_lifetime_minutes", 480),
        max_sessions=getattr(config.console, "max_sessions", 100),
        idle_timeout_minutes=getattr(config.console, "idle_timeout_minutes", 60),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        session_manager_attr = getattr(mcp, "_session_manager", None) or getattr(mcp, "session_manager", None)
        if session_manager_attr is not None:
            async with session_manager_attr.run():
                yield
        else:
            yield

    app = FastAPI(title="Linux Remote Management MCP", version="0.1.0", lifespan=lifespan)
    prefix = config.mcp.path.rstrip("/") or "/"

    @app.middleware("http")
    async def session_middleware(request: Request, call_next):
        """セッション管理ミドルウェア。全リクエストをトラッキングする。"""
        # MCP プレフィックス以外のリクエストはスキップ
        if request.url.path != prefix and not request.url.path.startswith(prefix + "/"):
            return await call_next(request)

        # Authorization ヘッダーからセッションを特定
        header = request.headers.get("Authorization", "")
        session = None
        if header.startswith("Bearer "):
            from .auth import authenticate_raw_token
            raw = header[7:].strip()
            token = authenticate_raw_token(store, raw)
            if token is not None:
                # セッションIDがヘッダーにあれば既存セッションを取得、なければ新規作成
                session_id = request.headers.get("X-Session-ID", "")
                if session_id:
                    session = session_manager.get_session(session_id)
                if session is None:
                    session = session_manager.create_session(
                        token_name=token.name,
                        server_id="",
                    )
                # セッションIDをレスポンスヘッダーに追加
                response = await call_next(request)
                response.headers["X-Session-ID"] = session.session_id
                return response

        return await call_next(request)

    @app.middleware("http")
    async def bearer_auth(request: Request, call_next):
        if request.url.path != prefix and not request.url.path.startswith(prefix + "/"):
            return Response(status_code=404, content="Not found")
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return Response(status_code=401, content="MCP Bearer token required")
        raw = header[7:].strip()
        token = authenticate_raw_token(store, raw)
        if token is None:
            return Response(status_code=401, content="Invalid or revoked MCP token")
        context = set_current_token(token)
        try:
            store.touch_last_used(token.id)
            return await call_next(request)
        finally:
            reset_current_token(context)

    # レート制限は最後に登録 (最外側) し、認証前の要求も含めて一律に適用する
    install_rate_limit(
        app,
        per_minute=config.console.rate_limit_per_minute,
        burst=config.console.rate_limit_burst,
        write_per_minute=config.console.rate_limit_write_per_minute,
        write_burst=config.console.rate_limit_write_burst,
        token_per_minute=config.console.rate_limit_token_per_minute,
        token_burst=config.console.rate_limit_token_burst,
    )

    asgi = mcp.http_app(transport="streamable-http", json_response=True, path="/")
    app.mount(prefix, asgi)
    return app