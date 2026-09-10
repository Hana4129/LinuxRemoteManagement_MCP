"""トークン期限切れ通知機能のテスト。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.token_notifier import (
    TokenExpiryNotifier,
    get_notifier,
    reset_notifier,
)


class TestTokenExpiryNotifier:
    def setup_method(self):
        reset_notifier()

    def teardown_method(self):
        reset_notifier()

    def _make_token(self, token_id: str, name: str, expires_in_days: float | None = None):
        token = {
            "id": token_id,
            "name": name,
            "prefix": "lra_AbCdEf…",
        }
        if expires_in_days is not None:
            exp = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
            token["expires_at"] = exp.isoformat()
        return token

    def test_no_expiry_no_notification(self):
        notifier = TokenExpiryNotifier()
        notifier.set_token_source(lambda: [self._make_token("tok1", "Test")])
        notifications = notifier.check_now()
        assert len(notifications) == 0

    def test_expired_token_detected(self):
        notifier = TokenExpiryNotifier()
        notifier.set_token_source(lambda: [self._make_token("tok1", "Test", -5)])
        notifications = notifier.check_now()
        assert len(notifications) == 1
        assert notifications[0]["type"] == "expired"
        assert notifications[0]["days_overdue"] == 5

    def test_reminder_triggered(self):
        notifier = TokenExpiryNotifier(reminder_days=[7, 3, 1])
        notifier.set_token_source(lambda: [self._make_token("tok1", "Test", 3)])
        notifications = notifier.check_now()
        assert len(notifications) == 1
        assert notifications[0]["type"] == "reminder"
        assert notifications[0]["days_remaining"] == 3

    def test_no_reminder_when_far(self):
        notifier = TokenExpiryNotifier(reminder_days=[7, 3, 1])
        notifier.set_token_source(lambda: [self._make_token("tok1", "Test", 30)])
        notifications = notifier.check_now()
        assert len(notifications) == 0

    def test_get_expiring_tokens(self):
        notifier = TokenExpiryNotifier()
        notifier.set_token_source(lambda: [
            self._make_token("tok1", "A", 10),
            self._make_token("tok2", "B", 60),
            self._make_token("tok3", "C", -1),
        ])
        expiring = notifier.get_expiring_tokens(within_days=30)
        assert len(expiring) == 1
        assert expiring[0]["token_id"] == "tok1"

    def test_multiple_tokens(self):
        notifier = TokenExpiryNotifier(reminder_days=[30])
        notifier.set_token_source(lambda: [
            self._make_token("tok1", "A", 10),
            self._make_token("tok2", "B", 5),
            self._make_token("tok3", "C", -1),
        ])
        notifications = notifier.check_now()
        # tok1 and tok2 get reminders, tok3 gets expired
        assert len(notifications) == 3

    def test_send_without_webhook(self):
        notifier = TokenExpiryNotifier(webhook_url="")
        result = notifier.send_notifications([{"type": "expired"}])
        assert result is False

    def test_notified_set_prevents_duplicates(self):
        notifier = TokenExpiryNotifier(reminder_days=[7])
        notifier.set_token_source(lambda: [self._make_token("tok1", "Test", 3)])
        n1 = notifier.check_now()
        assert len(n1) == 1
        n2 = notifier.check_now()
        # Should not re-notify for the same reminder
        assert len(n2) == 0


class TestGlobalNotifier:
    def setup_method(self):
        reset_notifier()

    def teardown_method(self):
        reset_notifier()

    def test_get_notifier(self):
        notifier = get_notifier(check_interval_minutes=30)
        assert notifier is not None
        assert notifier._check_interval_seconds == 1800

    def test_reset_notifier(self):
        n1 = get_notifier()
        reset_notifier()
        n2 = get_notifier()
        assert n1 is not n2
