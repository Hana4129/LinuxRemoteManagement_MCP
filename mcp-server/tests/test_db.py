"""TokenStore (db.py) の単体テスト。"""
from __future__ import annotations

import pytest

from app.db import TokenStore
from app.tokens import generate_token


def test_create_and_get_by_raw(store: TokenStore):
    record, raw = store.create_token(name="ci", server_ids=["dev-web-01"], scope="readonly", expires_in_days=7)
    assert raw.startswith("lra_")
    assert record.id and record.name == "ci"
    assert record.server_ids == ["dev-web-01"]
    assert record.scope == "readonly"
    assert record.active

    fetched = store.get_by_raw(raw)
    assert fetched is not None
    assert fetched.id == record.id
    # 生トークンはレコード一覧には現れない
    listed = store.list_tokens()
    assert all(t.token_raw == "" for t in listed)


def test_get_by_raw_unknown_token(store: TokenStore):
    assert store.get_by_raw("lra_" + "f" * 64) is None


def test_find_token_for_server_scope(store: TokenStore):
    store.create_token(name="ro", server_ids=["dev-web-01"], scope="readonly")
    ro = store.find_token_for_server("dev-web-01", scope="readonly")
    assert ro is not None and ro.scope == "readonly"
    # operator は無い
    assert store.find_token_for_server("dev-web-01", scope="operator") is None
    # 未登録サーバーは無い
    assert store.find_token_for_server("no-such", scope="readonly") is None


def test_wildcard_token_matches_any_server(store: TokenStore):
    store.create_token(name="all", server_ids=["*"], scope="operator")
    tok = store.find_token_for_server("any-server-id", scope="operator")
    assert tok is not None


def test_import_token_roundtrip(store: TokenStore):
    raw = generate_token()
    rec = store.import_token(name="ext", raw=raw, server_ids=["dev-db-01"], scope="operator", store_raw=True)
    assert rec.token_raw == raw
    got = store.get_by_raw(raw)
    assert got is not None and got.id == rec.id and got.scope == "operator"


def test_import_token_requires_server_ids(store: TokenStore):
    with pytest.raises(ValueError):
        store.import_token(name="bad", raw=generate_token(), server_ids=[], scope="readonly")


def test_revoke_disables_token(store: TokenStore):
    record, raw = store.create_token(name="t", server_ids=["dev-web-01"], scope="readonly")
    assert store.revoke_token(record.id) is True
    # 二度目は失敗 (既に失効済み)
    assert store.revoke_token(record.id) is False
    fetched = store.get_token(record.id)
    assert fetched is not None and not fetched.enabled and not fetched.active
    assert store.get_by_raw(raw).active is False
    assert store.find_token_for_server("dev-web-01", scope="readonly") is None


def test_delete_removes_record(store: TokenStore):
    record, _ = store.create_token(name="t", server_ids=["dev-web-01"], scope="readonly")
    assert store.delete_token(record.id) is True
    assert store.get_token(record.id) is None
    assert store.delete_token(record.id) is False


def test_touch_last_used(store: TokenStore):
    record, _ = store.create_token(name="t", server_ids=["dev-web-01"], scope="readonly")
    assert record.last_used_at is None
    store.touch_last_used(record.id)
    assert store.get_token(record.id).last_used_at is not None
