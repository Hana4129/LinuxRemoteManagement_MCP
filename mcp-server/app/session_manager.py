"""MCP セッション管理機能。

セッションタイムアウト、セッション数制限、アイドルタイムアウト機能を提供する。

設定項目 (config.yml):
    session_timeout_minutes: セッションの最大存続時間 (分)
    max_sessions: 同時許可する最大セッション数
    idle_timeout_minutes: アイドルタイムアウト時間 (分)
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class SessionInfo:
    """セッション情報を保持する。"""
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_active_at: float = field(default_factory=time.time)
    token_name: str = ""
    server_id: str = ""

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_active_at

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    def touch(self) -> None:
        self.last_active_at = time.time()


class SessionLimitExceeded(Exception):
    """セッション数制限超過エラー。"""
    pass


class SessionManager:
    """MCP セッションの作成・追跡・期限切れ管理を行う。"""

    def __init__(
        self,
        session_timeout_minutes: int = 480,
        max_sessions: int = 100,
        idle_timeout_minutes: int = 60,
    ) -> None:
        self._session_timeout_seconds = session_timeout_minutes * 60
        self._max_sessions = max_sessions
        self._idle_timeout_seconds = idle_timeout_minutes * 60
        self._sessions: Dict[str, SessionInfo] = {}
        self._lock = threading.RLock()
        self._cleanup_interval = 60
        self._last_cleanup = time.time()

    def create_session(self, token_name: str = "", server_id: str = "") -> SessionInfo:
        """新規セッションを作成する。"""
        with self._lock:
            self._maybe_cleanup()
            if len(self._sessions) >= self._max_sessions:
                self._evict_oldest_idle()
            if len(self._sessions) >= self._max_sessions:
                raise SessionLimitExceeded(
                    f"Maximum sessions ({self._max_sessions}) reached"
                )
            session_id = str(uuid4())
            session = SessionInfo(
                session_id=session_id,
                token_name=token_name,
                server_id=server_id,
            )
            self._sessions[session_id] = session
            logger.info("Session created: %s (total: %s)", session_id[:8], len(self._sessions))
            return session

    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """セッションを取得し、活動時刻を更新する。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if self._is_expired(session):
                del self._sessions[session_id]
                logger.info("Session expired: %s", session_id[:8])
                return None
            session.touch()
            return session

    def destroy_session(self, session_id: str) -> bool:
        """セッションを破棄する。"""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.info("Session destroyed: %s", session_id[:8])
                return True
            return False

    def active_count(self) -> int:
        """有効なセッション数を返す。"""
        with self._lock:
            self._maybe_cleanup()
            return len(self._sessions)

    def get_all_sessions(self) -> list[dict[str, Any]]:
        """全セッション情報をダンプする (管理用)。"""
        with self._lock:
            return [
                {
                    "session_id": s.session_id,
                    "created_at": s.created_at,
                    "last_active_at": s.last_active_at,
                    "idle_seconds": s.idle_seconds,
                    "age_seconds": s.age_seconds,
                    "token_name": s.token_name,
                    "server_id": s.server_id,
                }
                for s in self._sessions.values()
            ]

    def _is_expired(self, session: SessionInfo) -> bool:
        """セッションが期限切れかどうか判定する。"""
        if session.age_seconds > self._session_timeout_seconds:
            return True
        if session.idle_seconds > self._idle_timeout_seconds:
            return True
        return False

    def _maybe_cleanup(self) -> None:
        """定期的に期限切れセッションをクリーンアップする。"""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        expired = [sid for sid, s in self._sessions.items() if self._is_expired(s)]
        for sid in expired:
            del self._sessions[sid]
        if expired:
            logger.info("Cleaned up %d expired sessions", len(expired))

    def _evict_oldest_idle(self) -> None:
        """最も古いアイドルセッションを破棄する。"""
        if not self._sessions:
            return
        oldest_id = min(
            self._sessions.keys(),
            key=lambda sid: self._sessions[sid].last_active_at,
        )
        del self._sessions[oldest_id]
        logger.info("Evicted oldest idle session: %s", oldest_id[:8])


# グローバルインスタンス
_default_manager: Optional[SessionManager] = None


def get_session_manager(
    session_timeout_minutes: int = 480,
    max_sessions: int = 100,
    idle_timeout_minutes: int = 60,
) -> SessionManager:
    """グローバルな SessionManager インスタンスを取得する。"""
    global _default_manager
    if _default_manager is None:
        _default_manager = SessionManager(
            session_timeout_minutes=session_timeout_minutes,
            max_sessions=max_sessions,
            idle_timeout_minutes=idle_timeout_minutes,
        )
    return _default_manager


def reset_session_manager() -> None:
    """テスト用にマネージャーをリセットする。"""
    global _default_manager
    _default_manager = None
