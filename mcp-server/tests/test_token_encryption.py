"""トークン保存時暗号化 (db.py × secretbox.py) の統合テスト。

Issue: [Security] 生トークン保存問題の解決 — 完了条件の検証:
- 生トークンが DB に (平文で) 保存されない
- トークン発行時は生トークンを1回だけ返し、2回目は取得不可
- 既存トークンのハッシュとの互換性を維持
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from app.db import TokenStore
from app.secretbox import DEFAULT_KEY_FILE_NAME, ENV_KEY_NAME
from app.tokens import generate_token, hash_token


def _db_bytes(db_path: Path) -> bytes:
    """DB本体 + WAL ファイルのバイト列を返す (平文混入チェック用)。"""
    data = db_path.read_bytes()
    wal = db_path.with_name(db_path.name + "-wal")
    if wal.exists():
        data += wal.read_bytes()
    return data


# ---- 完了条件1: 生トークンが平文で保存されない ----

def test_created_token_not_stored_as_plaintext(store: TokenStore, tmp_path):
    record, raw = store.create_token(name="ci", server_ids=["dev-web-01"], scope="readonly")
    db_data = _db_bytes(tmp_path / "tokens.db")
    assert raw.encode() not in db_data, "生トークンが平文でDBに保存されている"
    # 照合用ハッシュは保存されている
    assert hash_token(raw).encode() in db_data


def test_agent_credential_not_stored_as_plaintext(store: TokenStore, tmp_path):
    raw = "agent-secret-token-value"
    store.create_agent_credential("dev-web-01", "agent", raw, agent_token_id="agt-1")
    db_data = _db_bytes(tmp_path / "tokens.db")
    assert raw.encode() not in db_data, "Agent credentialの生値が平文でDBに保存されている"
    found = store.find_agent_credential("dev-web-01")
    assert found is not None and found.token_raw == raw, "Agent呼び出し用に復号できる"


def test_rotated_token_not_stored_as_plaintext(store: TokenStore, tmp_path):
    record, _raw = store.create_token(name="t", server_ids=["dev-web-01"], scope="readonly")
    rotated = store.rotate_token(record.id, grace_period_days=1)
    assert rotated.token_raw.encode() not in _db_bytes(tmp_path / "tokens.db")

    credential, _ = store.generate_agent_credential(
        server_id="dev-web-01", name="agent", agent_token_id="agt-rot"
    )
    rotated_cred, cred_raw = store.rotate_agent_credential(credential.id, grace_period_days=1)
    assert cred_raw.encode() not in _db_bytes(tmp_path / "tokens.db")
    assert rotated_cred.agent_token_id == "agt-rot"


# ---- 完了条件2: 発行時1回だけ返し、2回目は取得不可 ----

def test_token_raw_returned_once(store: TokenStore):
    record, raw = store.create_token(name="ci", server_ids=["dev-web-01"], scope="readonly")
    assert raw
    got = store.get_token(record.id)
    assert got is not None and got.token_raw == "", "管理系readでは生値を返さない"
    assert all(t.token_raw == "" for t in store.list_tokens())


def test_rotated_token_raw_returned_once(store: TokenStore):
    record, _ = store.create_token(name="t", server_ids=["dev-web-01"], scope="readonly")
    rotated = store.rotate_token(record.id, grace_period_days=1)
    assert rotated.token_raw, "ローテーション直後は1回だけ返す"
    refetched = store.get_token(rotated.id)
    assert refetched is not None and refetched.token_raw == "", "2回目は取得不可"


def test_agent_credential_listing_hides_raw(store: TokenStore):
    credential, raw = store.generate_agent_credential(
        server_id="dev-web-01", name="agent", agent_token_id="agt-1"
    )
    assert credential.token_raw == raw  # 発行直後の戻り値のみ
    assert all(c.token_raw == "" for c in store.list_agent_credentials())
    got = store.get_agent_credential(credential.id)
    assert got is not None and got.token_raw == raw  # 内部利用 (API応答には含まれない)


# ---- 完了条件3: ハッシュ互換性の維持 ----

def test_get_by_raw_hash_compatibility(store: TokenStore):
    record, raw = store.create_token(name="ci", server_ids=["dev-web-01"], scope="readonly")
    fetched = store.get_by_raw(raw)
    assert fetched is not None and fetched.id == record.id


def test_find_token_for_server_decrypts_for_agent_forwarding(store: TokenStore):
    _record, raw = store.create_token(name="t", server_ids=["dev-web-01"], scope="readonly")
    found = store.find_token_for_server("dev-web-01", scope="readonly")
    assert found is not None and found.token_raw == raw
