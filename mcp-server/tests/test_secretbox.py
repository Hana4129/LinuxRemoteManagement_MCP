"""secretbox.py (トークン保存時暗号化) の単体テスト。"""
from __future__ import annotations

import base64
import os

import pytest

from app.secretbox import (
    DEFAULT_KEY_FILE_NAME,
    ENV_KEY_NAME,
    SecretBox,
    SecretBoxError,
    is_encrypted,
    load_or_create_key,
    parse_key,
    resolve_secret_box,
)


def test_roundtrip():
    box = SecretBox(os.urandom(32))
    ciphertext = box.encrypt("lra_secret-value")
    assert is_encrypted(ciphertext)
    assert "lra_secret" not in ciphertext  # 平文が混入しない
    assert ciphertext.startswith("enc.v1.")
    assert box.decrypt(ciphertext) == "lra_secret-value"


def test_encrypt_is_randomized():
    """同じ平文でも nonce により毎回異なる暗号文になる。"""
    box = SecretBox(os.urandom(32))
    assert box.encrypt("same-value") != box.encrypt("same-value")


def test_tamper_is_detected():
    box = SecretBox(os.urandom(32))
    ciphertext = box.encrypt("value")
    suffix = "aa" if not ciphertext.endswith("aa") else "bb"
    tampered = ciphertext[:-2] + suffix
    with pytest.raises(SecretBoxError):
        box.decrypt(tampered)


def test_wrong_key_fails():
    ciphertext = SecretBox(os.urandom(32)).encrypt("value")
    with pytest.raises(SecretBoxError):
        SecretBox(os.urandom(32)).decrypt(ciphertext)


def test_decrypt_rejects_plaintext():
    box = SecretBox(os.urandom(32))
    with pytest.raises(SecretBoxError):
        box.decrypt("lra_plain-token")


def test_parse_key_formats():
    key = os.urandom(32)
    assert parse_key(key) == key
    assert parse_key(key.hex()) == key
    assert parse_key(base64.b64encode(key).decode()) == key
    assert parse_key(base64.urlsafe_b64encode(key).decode()) == key
    with pytest.raises(ValueError):
        parse_key("too-short")


def test_parse_key_rejects_wrong_length():
    with pytest.raises(ValueError):
        parse_key(os.urandom(16).hex())


def test_key_file_created_and_reused(tmp_path):
    key_file = tmp_path / DEFAULT_KEY_FILE_NAME
    key1 = load_or_create_key(key_file)
    assert key_file.exists()
    key2 = load_or_create_key(key_file)
    assert key1 == key2


def test_resolve_explicit_key():
    assert isinstance(resolve_secret_box(explicit_key=os.urandom(32)), SecretBox)


def test_resolve_requires_key_source(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_KEY_NAME, raising=False)
    with pytest.raises(ValueError):
        resolve_secret_box()  # キーもキーファイルも無い
    assert isinstance(resolve_secret_box(key_file=tmp_path / "k.key"), SecretBox)


def test_resolve_env_key(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_KEY_NAME, os.urandom(32).hex())
    assert isinstance(resolve_secret_box(), SecretBox)


def test_resolve_invalid_env_key_fails(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_KEY_NAME, "not-a-valid-key")
    with pytest.raises(ValueError):
        resolve_secret_box(key_file=tmp_path / "k.key")
