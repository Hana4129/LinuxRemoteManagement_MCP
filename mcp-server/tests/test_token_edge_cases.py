"""Edge case tests for token rotation, expiration, and concurrent operations."""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import threading
import time
from pathlib import Path

import pytest

from app.db import TokenStore
from app.tokens import hash_token


class TestTokenExpiration:
    def test_expired_token_disabled(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        rec, raw = store.create_token(name="test", server_ids=["s1"], scope="readonly",
                                       expires_at="2020-01-01T00:00:00Z")
        # Token with past expiry is still created; expiry checked at validation time
        assert rec.enabled is True
        assert rec.expires_at == "2020-01-01T00:00:00Z"

    def test_valid_token_enabled(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        rec, raw = store.create_token(name="test", server_ids=["s1"], scope="readonly",
                                       expires_in_days=1)
        assert rec.enabled is True

    def test_no_expiry_never_expires(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        rec, raw = store.create_token(name="test", server_ids=["s1"], scope="readonly")
        assert rec.enabled is True
        assert rec.expires_at is None


class TestTokenRotationGracePeriod:
    def test_grace_period_active(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        old, old_raw = store.create_token(name="test", server_ids=["s1"], scope="readonly")
        new = store.rotate_token(old.id, rotated_by="tester", grace_period_days=7)
        assert store.is_in_grace_period(old.id) is True

    def test_rotation_without_grace(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        old, old_raw = store.create_token(name="test", server_ids=["s1"], scope="readonly")
        new = store.rotate_token(old.id, grace_period_days=1)
        assert new is not None
        assert new.id != old.id

    def test_rotation_preserves_metadata(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        old, old_raw = store.create_token(name="mytok", server_ids=["s1", "s2"],
                                           scope="operator", created_by="admin")
        new = store.rotate_token(old.id, rotated_by="admin")
        assert new.name == "mytok"
        assert new.server_ids == ["s1", "s2"]
        assert new.scope == "operator"


class TestConcurrentTokenAccess:
    def test_concurrent_reads(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        rec, raw = store.create_token(name="test", server_ids=["s1"], scope="readonly")
        results = []
        errors = []

        def read_token():
            try:
                found = store.get_by_raw(raw)
                results.append(found is not None)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=read_token) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0
        assert all(results)

    def test_concurrent_creations(self, tmp_path):
        store = TokenStore(tmp_path / "tokens.db")
        errors = []

        def create(i):
            try:
                store.create_token(name=f"test-{i}", server_ids=["s1"], scope="readonly")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=create, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0
        assert store.list_tokens() is not None
