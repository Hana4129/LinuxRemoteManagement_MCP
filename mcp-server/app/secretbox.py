"""保存時暗号化ユーティリティ (AES-256-GCM)。

``tokens.token_raw`` / ``agent_credentials.token_raw`` に保存する生トークンを
平文のまま SQLite に書き込まないためのモジュール。

保存形式 (token_raw カラム内):

    enc.v1.<nonce base64url>.<ciphertext base64url>

キー解決順 (:func:`resolve_secret_box`):

1. 明示的に渡されたキー (32バイト)
2. 環境変数 ``LRM_TOKEN_ENCRYPTION_KEY`` (32バイトの hex / base64 / base64url)
3. キーファイル (既定: ``<tokens.db と同じディレクトリ>/token_encryption.key``、
   無ければ CSPRNG で生成して 0600 で保存)

キーを DB とは別の場所に置くことで、DB ファイル単体の漏洩では
生トークンを復元できないようにする。トークンの照合に使う
SHA-256 ハッシュ (``token_hash``) は暗号化の影響を受けない。
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "DEFAULT_KEY_FILE_NAME",
    "ENV_KEY_NAME",
    "SecretBox",
    "SecretBoxError",
    "is_encrypted",
    "load_or_create_key",
    "parse_key",
    "resolve_secret_box",
]

ENV_KEY_NAME = "LRM_TOKEN_ENCRYPTION_KEY"
DEFAULT_KEY_FILE_NAME = "token_encryption.key"

_PREFIX = "enc.v1."
_KEY_BYTES = 32
_NONCE_BYTES = 12


class SecretBoxError(Exception):
    """復号に失敗した (キー不一致・改ざん・形式不正)。"""


def is_encrypted(value: str | None) -> bool:
    """値が保存時暗号化フォーマットなら True を返す。"""
    return bool(value) and value.startswith(_PREFIX)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse_key(value: bytes | str) -> bytes:
    """キー material を 32バイトに正規化する。

    hex (64文字) / base64 / base64url / 生32バイトのいずれかを受け付ける。
    """
    if isinstance(value, bytes):
        raw = value
    else:
        text = value.strip()
        if not text:
            raise ValueError("暗号化キーが空です")
        candidates: list[bytes] = []
        if len(text) == _KEY_BYTES * 2:
            try:
                candidates.append(bytes.fromhex(text))
            except ValueError:
                pass
        for decoder in (_b64d, base64.b64decode):
            try:
                candidates.append(decoder(text))
            except (binascii.Error, ValueError):
                pass
        raw = next((c for c in candidates if len(c) == _KEY_BYTES), None)
        if raw is None:
            raise ValueError(
                f"暗号化キーは {_KEY_BYTES} バイト (hex/base64) で指定してください"
            )
    if len(raw) != _KEY_BYTES:
        raise ValueError(f"暗号化キーは {_KEY_BYTES} バイトである必要があります (実長: {len(raw)})")
    return raw


def load_or_create_key(key_file: str | Path) -> bytes:
    """キーファイルからキーを読み、無ければ CSPRNG で生成して保存する。

    並行起動時の二重生成を避けるため排他生成 (``x`` モード) を使い、
    先に作られた側のキーを採用する。
    """
    path = Path(key_file)
    if path.exists():
        data = path.read_bytes().strip()
        try:
            # テキスト (hex/base64) として解釈できなければ生32バイトとみなす
            return parse_key(data.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return parse_key(data)

    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(_KEY_BYTES)
    try:
        # 排他生成: 同時起動時に既に作られていたらそのキーを使う
        with open(path, "xb") as fh:
            fh.write(_b64e(key).encode("ascii"))
    except FileExistsError:
        return load_or_create_key(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows 等では chmod が効かないことがある
    return key


class SecretBox:
    """AES-256-GCM による保存時暗号化。"""

    def __init__(self, key: bytes | str):
        self._key = parse_key(key)
        self._aes = AESGCM(self._key)

    def encrypt(self, plaintext: str) -> str:
        """平文を ``enc.v1.<nonce>.<ciphertext>`` 形式に暗号化する。"""
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = self._aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        return f"{_PREFIX}{_b64e(nonce)}.{_b64e(ciphertext)}"

    def decrypt(self, value: str) -> str:
        """暗号化値を復号する。失敗時は SecretBoxError。"""
        if not is_encrypted(value):
            raise SecretBoxError("暗号化フォーマットではありません")
        try:
            nonce_b64, ct_b64 = value[len(_PREFIX):].split(".", 1)
            plaintext = self._aes.decrypt(_b64d(nonce_b64), _b64d(ct_b64), None)
        except Exception as exc:  # noqa: BLE001 - InvalidTag等をすべてSecretBoxErrorへ
            raise SecretBoxError("復号に失敗しました (キー不一致または改ざん)") from exc
        return plaintext.decode("utf-8")


def resolve_secret_box(
    *,
    explicit_key: bytes | str | None = None,
    key_file: str | Path | None = None,
) -> SecretBox:
    """キー解決順に従い SecretBox を構築する。

    優先順: 明示キー → 環境変数 ``LRM_TOKEN_ENCRYPTION_KEY`` → キーファイル。
    """
    if explicit_key is not None:
        return SecretBox(parse_key(explicit_key))
    env_value = os.environ.get(ENV_KEY_NAME, "").strip()
    if env_value:
        return SecretBox(parse_key(env_value))
    if key_file is not None:
        return SecretBox(load_or_create_key(key_file))
    raise ValueError(
        f"トークン暗号化キーが指定されていません (key_file または環境変数 {ENV_KEY_NAME})"
    )
