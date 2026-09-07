"""管理コンソールの認証・認可ミドルウェア。"""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING

from app.auth import authenticate_raw_token, current_token, reset_current_token, set_current_token

if TYPE_CHECKING:
    from app.db import TokenRecord

_current_principal: ContextVar[dict | None] = ContextVar("current_console_principal", default=None)


def set_current_principal(principal: dict):
    return _current_principal.set(principal)


def reset_current_principal(context) -> None:
    _current_principal.reset(context)


def current_principal() -> dict | None:
    return _current_principal.get()
