"""Rate limiting for MCP Server.

Provides token-bucket rate limiting per client IP and per token.
Configurable via config.yml (console.rate_limit_per_minute, console.rate_limit_burst).
"""

from __future__ import annotations

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
