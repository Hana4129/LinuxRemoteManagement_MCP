"""tokens.py の単体テスト。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.tokens import (
    expiry_iso,
    generate_token,
    hash_token,
    is_expired,
    new_token_id,
    now_iso,
    token_prefix,
    verify_token,
)


def test_generate_token_format_and_uniqueness():
    t1, t2 = generate_token(), generate_token()
    assert t1 != t2
    assert t1.startswith("lra_")
    # 64 bytes -> 86 base64url chars + "lra_" prefix (secrets.token_urlsafe(64))
    assert len(t1) == 4 + 86


def test_hash_token_is_stable_and_verifiable():
    raw = generate_token()
    h1, h2 = hash_token(raw), hash_token(raw)
    assert h1 == h2
    assert h1 != hash_token(raw + "x")
    assert verify_token(raw, h1)
    assert not verify_token("wrong", h1)


def test_token_prefix_masks_secret():
    raw = "lra_" + "a" * 64
    p = token_prefix(raw)
    assert "a" * 64 not in p
    assert p.endswith("…")  # 単一の省略文字
    assert p[:12] == raw[:12]  # 先頭12文字のみ表示
    assert len(p) == 13


def test_new_token_id_prefixed():
    assert new_token_id().startswith("tok_")


def test_now_iso_has_timezone():
    assert now_iso().endswith("+00:00") or "+00:00" in now_iso()


def test_expiry_iso_none_for_unlimited():
    assert expiry_iso(None) is None
    assert expiry_iso(0) is None


def test_expiry_iso_future_date():
    exp = expiry_iso(30)
    assert exp is not None
    dt = datetime.fromisoformat(exp)
    assert dt > datetime.now(timezone.utc) + timedelta(days=29)


def test_is_expired():
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert not is_expired(None)
    assert not is_expired(future)
    assert is_expired(past)
