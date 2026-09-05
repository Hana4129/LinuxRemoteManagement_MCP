"""認証済みMCP主体をリクエスト単位で保持する。"""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .db import TokenRecord

_current_token: ContextVar[TokenRecord | None] = ContextVar("current_mcp_token", default=None)
_current_principal: ContextVar[dict | None] = ContextVar("current_console_principal", default=None)


def set_current_token(token: TokenRecord):
    return _current_token.set(token)


def reset_current_token(token_context) -> None:
    _current_token.reset(token_context)


def current_token() -> TokenRecord | None:
    return _current_token.get()


def set_current_principal(principal: dict):
    return _current_principal.set(principal)


def reset_current_principal(context) -> None:
    _current_principal.reset(context)


def current_principal() -> dict | None:
    return _current_principal.get()


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