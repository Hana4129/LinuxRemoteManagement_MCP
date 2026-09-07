"""Rate limiting for MCP Server.

Provides token-bucket rate limiting per client IP and per token.
Configurable via config.yml (console.rate_limit_per_minute, console.rate_limit_burst,
and the optional write/token specific limits below).
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from threading import Lock
from typing import Dict

logger = logging.getLogger(__name__)


@dataclass
class _Visitor:
    tokens: float = 0.0
    last_seen: float = 0.0


class RateLimiter:
    """Token-bucket rate limiter."""

    def __init__(self, per_minute: int = 60, burst: int = 10):
        self.per_minute = max(1, per_minute)
        self.burst = max(1, burst)
        self._visitors: Dict[str, _Visitor] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""

        now = time.monotonic()
        with self._lock:
            v = self._visitors.get(key)
            if v is None:
                self._visitors[key] = _Visitor(
                    tokens=float(self.burst) - 1.0, last_seen=now
                )
                return True
            elapsed = now - v.last_seen
            v.tokens += elapsed * self.per_minute / 60.0
            if v.tokens > self.burst:
                v.tokens = float(self.burst)
            v.last_seen = now
            if v.tokens < 1.0:
                return False
            v.tokens -= 1.0
            return True

    def cleanup(self, max_age_seconds: float = 300.0) -> None:
        """Remove stale entries."""

        now = time.monotonic()
        with self._lock:
            stale = [k for k, v in self._visitors.items() if now - v.last_seen > max_age_seconds]
            for k in stale:
                del self._visitors[k]


_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _bearer_token_key(authorization: str) -> str:
    """Authorization ヘッダーから Bearer トークンのハッシュ (キー用) を作る。"""

    if not authorization.startswith("Bearer "):
        return ""
    raw = authorization[7:].strip()
    if not raw:
        return ""
    # 生トークンをメモリ上に残さないよう SHA-256 でハッシュ化してキーにする
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def install_rate_limit(app, *, per_minute: int, burst: int,
                       write_per_minute: int = 0, write_burst: int = 0,
                       token_per_minute: int = 0, token_burst: int = 0) -> bool:
    """FastAPI アプリへ「IP + トークン複合・操作別」のレート制限ミドルウェアを追加する。

    - ``per_minute`` / ``burst``: 各クライアント (IP, もしくは IP+トークン) の基本バケット
    - ``write_per_minute`` / ``write_burst``: 操作系 (POST/PUT/PATCH/DELETE) の別バケット。
      0 なら基本値へフォールバック
    - ``token_per_minute`` / ``token_burst``: Bearer トークン単位の分離バケット。
      0 なら基本値へフォールバック
    - トークン + IP の複合キーで計上するため、同一 NAT 配下の別トークンを区別できる
    - 有効な設定 (per_minute > 0 かつ burst > 0) の場合のみ登録し、True を返す
    """

    if per_minute <= 0 or burst <= 0:
        return False
    base_limiter = RateLimiter(per_minute=per_minute, burst=burst)
    write_limiter = RateLimiter(
        per_minute=write_per_minute or per_minute, burst=write_burst or burst
    )
    token_limiter = RateLimiter(
        per_minute=token_per_minute or per_minute, burst=token_burst or burst
    )

    @app.middleware("http")
    async def _rate_limit(request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        token_key = _bearer_token_key(request.headers.get("Authorization", ""))
        # キー: IP 単位と IP+トークン単位の両方を計上する
        ip_key = f"ip:{client_ip}"
        composite_key = f"{ip_key}|tok:{token_key}" if token_key else ip_key
        limiter = write_limiter if request.method in _MUTATING_METHODS else base_limiter

        if not limiter.allow(composite_key):
            return _rate_limited_response()
        if token_key and not token_limiter.allow(token_key):
            return _rate_limited_response()
        return await call_next(request)

    return True


def _rate_limited_response():
    from fastapi import Response

    return Response(
        status_code=429,
        content="429 Too Many Requests",
        headers={"Retry-After": "60"},
    )
