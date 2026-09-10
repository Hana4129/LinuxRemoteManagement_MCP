"""トークン期限切れ通知・リマインダー機能。"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib import request as urllib_request
from urllib.error import URLError

logger = logging.getLogger(__name__)


class TokenExpiryNotifier:
    """トークン期限切れ通知を管理する。"""

    def __init__(
        self,
        reminder_days: list[int] | None = None,
        webhook_url: str = "",
        webhook_secret: str = "",
        check_interval_minutes: int = 60,
    ) -> None:
        self._reminder_days = reminder_days or [30, 14, 7, 3, 1]
        self._webhook_url = webhook_url
        self._webhook_secret = webhook_secret
        self._check_interval_seconds = check_interval_minutes * 60
        self._stop_event = threading.Event()
        self._checker_thread: threading.Thread | None = None
        self._get_tokens_callback: Callable[[], list[dict[str, Any]]] | None = None
        self._notified: set[str] = set()

    def set_token_source(self, callback: Callable[[], list[dict[str, Any]]]) -> None:
        self._get_tokens_callback = callback

    def start(self) -> None:
        if self._checker_thread is not None:
            return
        self._stop_event.clear()
        self._checker_thread = threading.Thread(
            target=self._check_loop, daemon=True, name="token-expiry-checker"
        )
        self._checker_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._checker_thread is not None:
            self._checker_thread.join(timeout=10)
            self._checker_thread = None

    def check_now(self) -> list[dict[str, Any]]:
        notifications: list[dict[str, Any]] = []
        if self._get_tokens_callback is None:
            return notifications
        tokens = self._get_tokens_callback()
        now = datetime.now(timezone.utc)
        for token in tokens:
            expires_at = token.get("expires_at")
            if not expires_at:
                continue
            try:
                exp_dt = datetime.fromisoformat(expires_at)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            delta = exp_dt - now
            days_until = delta.days
            if days_until < 0:
                notifications.append({
                    "type": "expired",
                    "token_id": token.get("id"),
                    "token_name": token.get("name"),
                    "prefix": token.get("prefix", ""),
                    "expired_at": expires_at,
                    "days_overdue": abs(days_until),
                })
            else:
                for rd in self._reminder_days:
                    if days_until <= rd:
                        key = f"{token.get('id')}:{rd}"
                        if key not in self._notified:
                            notifications.append({
                                "type": "reminder",
                                "token_id": token.get("id"),
                                "token_name": token.get("name"),
                                "prefix": token.get("prefix", ""),
                                "expires_at": expires_at,
                                "days_remaining": days_until,
                            })
                            self._notified.add(key)
                        break
        return notifications

    def send_notifications(self, notifications: list[dict[str, Any]]) -> bool:
        if not self._webhook_url or not notifications:
            return False
        payload = {
            "event": "token_expiry_notification",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notifications": notifications,
            "total": len(notifications),
        }
        return self._send_webhook(payload)

    def _send_webhook(self, payload: dict[str, Any]) -> bool:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "Linux-MCP-Notifier/0.1"}
        if self._webhook_secret:
            sig = hmac.new(self._webhook_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Signature"] = f"sha256={sig}"
        req = urllib_request.Request(self._webhook_url, data=body, headers=headers, method="POST")
        try:
            with urllib_request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201, 202, 204)
        except (URLError, OSError):
            return False

    def _check_loop(self) -> None:
        while not self._stop_event.wait(timeout=self._check_interval_seconds):
            try:
                n = self.check_now()
                if n:
                    self.send_notifications(n)
            except Exception:
                logger.exception("Token expiry check failed")

    def get_expiring_tokens(self, within_days: int = 30) -> list[dict[str, Any]]:
        if self._get_tokens_callback is None:
            return []
        tokens = self._get_tokens_callback()
        now = datetime.now(timezone.utc)
        result = []
        for token in tokens:
            expires_at = token.get("expires_at")
            if not expires_at:
                continue
            try:
                exp_dt = datetime.fromisoformat(expires_at)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            delta = exp_dt - now
            if 0 <= delta.days <= within_days:
                result.append({
                    "token_id": token.get("id"),
                    "token_name": token.get("name"),
                    "expires_at": expires_at,
                    "days_remaining": delta.days,
                })
        return result

_default_notifier: Optional[TokenExpiryNotifier] = None


def get_notifier(
    reminder_days: list[int] | None = None,
    webhook_url: str = "",
    webhook_secret: str = "",
    check_interval_minutes: int = 60,
) -> TokenExpiryNotifier:
    global _default_notifier
    if _default_notifier is None:
        _default_notifier = TokenExpiryNotifier(
            reminder_days=reminder_days,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            check_interval_minutes=check_interval_minutes,
        )
    return _default_notifier


def reset_notifier() -> None:
    global _default_notifier
    if _default_notifier is not None:
        _default_notifier.stop()
    _default_notifier = None