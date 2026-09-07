"""MCP主体のトークンをリクエスト単位で保持する (app/shared モジュール)。"""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.db import TokenRecord

_current_token: ContextVar[TokenRecord | None] = ContextVar("current_mcp_token", default=None)


def set_current_token(token: TokenRecord):
    return _current_token.set(token)


def reset_current_token(token_context) -> None:
    _current_token.reset(token_context)


def current_token() -> TokenRecord | None:
    return _current_token.get()


def authenticate_raw_token(store, raw: str):
    """Return an active token record for a supplied MCP credential."""
    if not raw:
        return None
    token = store.get_by_raw(raw)
    if token is None or not token.active:
        return None
    if token.principal_id and not store.principal_active(token.principal_id):
        return None
    return token
