"""APIトークンの生成・ハッシュ化ユーティリティ。

設計書 §6 / §7 / §8 より:
  - トークンは CSPRNG (secrets) による十分に長いランダム値
  - token_id / created_at / expires_at / scope / server_id を紐付けて管理
  - ログや一覧表示には生値を露出させない

保存について (Issue: 生トークン保存問題の解決):
  - 照合用の SHA-256 ハッシュ (``token_hash``) を常に保存する
  - MCP Server が Agent へ Bearer 認証するために必要な生値は、
    ``db.py`` が AES-256-GCM で暗号化してから SQLite に保存する (secretbox.py 参照)
  - 暗号化キーは DB 外 (環境変数 LRM_TOKEN_ENCRYPTION_KEY または
    data_dir/token_encryption.key) で管理し、DB ファイル単体の漏洩では復元できない
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

TOKEN_PREFIX = "lra_"
SCOPES: tuple[str, ...] = ("readonly", "operator")


def generate_token() -> str:
    """CSPRNG で 64 バイト (≈512bit) 相当のトークンを生成する。"""
    return TOKEN_PREFIX + secrets.token_urlsafe(64)


def hash_token(token: str) -> str:
    """トークンの SHA-256 ハッシュ (16進) を返す。照合用。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    """定時間比較でトークンを検証する。"""
    return hmac.compare_digest(hash_token(token), token_hash)


def token_prefix(token: str) -> str:
    """一覧表示用の先頭部分 (例: ``lra_AbCdEfGhIj…``)。"""
    if len(token) <= 12:
        return token + "…"
    return token[:12] + "…"


def new_token_id() -> str:
    return "tok_" + secrets.token_hex(6)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def expiry_iso(days: int | None) -> str | None:
    """有効期限の ISO 8601 文字列。``days`` が None/<=0 なら無期限。"""
    if not days or days <= 0:
        return None
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")


def is_expired(expires_at: str | None, now: datetime | None = None) -> bool:
    if not expires_at:
        return False
    try:
        exp = datetime.fromisoformat(expires_at)
    except ValueError:
        return True
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return current >= exp


def humanize_token_expiry(expires_at: str | None) -> str:
    if not expires_at:
        return "無期限"
    try:
        exp = datetime.fromisoformat(expires_at)
    except ValueError:
        return expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    delta = exp - datetime.now(timezone.utc)
    if delta.total_seconds() <= 0:
        return "期限切れ"
    days = delta.days
    if days >= 1:
        return f"{days + 1}日"
    hours = delta.total_seconds() / 3600
    if hours >= 1:
        return f"{hours:.0f}時間"
    return "数分"


def humanize_uptime(seconds: int | float | None) -> str:
    """エージェントが返す uptime_seconds を人間向けに整形する。"""
    if not seconds or seconds <= 0:
        return "不明"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days >= 1:
        return f"{days}d {hours}h"
    if hours >= 1:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
