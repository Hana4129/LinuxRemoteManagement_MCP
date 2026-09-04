"""APIトークンの SQLite ストア。

ファイルパーミッションは 0600 に設定する (POSIX)。
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Sequence

from .tokens import (
    expiry_iso,
    generate_token,
    hash_token,
    is_expired,
    new_token_id,
    now_iso,
    token_prefix,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    token_raw     TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    prefix        TEXT NOT NULL,
    server_ids    TEXT NOT NULL,
    scope         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    last_used_at  TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_by    TEXT,
    rotated_from  TEXT,
    grace_ends_at TEXT
);

CREATE TABLE IF NOT EXISTS token_rotations (
    id              TEXT PRIMARY KEY,
    old_token_id    TEXT NOT NULL,
    new_token_id    TEXT NOT NULL,
    rotated_at      TEXT NOT NULL,
    grace_ends_at   TEXT NOT NULL,
    rotated_by      TEXT,
    FOREIGN KEY (old_token_id) REFERENCES tokens(id),
    FOREIGN KEY (new_token_id) REFERENCES tokens(id)
);

CREATE INDEX IF NOT EXISTS idx_tokens_rotated_from ON tokens(rotated_from);
CREATE INDEX IF NOT EXISTS idx_token_rotations_old ON token_rotations(old_token_id);
CREATE INDEX IF NOT EXISTS idx_token_rotations_new ON token_rotations(new_token_id);
"""


@dataclass
class TokenRecord:
    id: str
    name: str
    token_hash: str
    prefix: str
    server_ids: list[str]
    scope: str
    created_at: str
    expires_at: str | None
    last_used_at: str | None
    enabled: bool
    token_raw: str = ""
    created_by: str | None = None
    rotated_from: str | None = None
    grace_ends_at: str | None = None

    @property
    def expired(self) -> bool:
        return is_expired(self.expires_at)

    @property
    def active(self) -> bool:
        return self.enabled and not self.expired

    def to_dict(self, include_token: bool = False) -> dict:
        data = {
            "id": self.id,
            "name": self.name,
            "prefix": self.prefix,
            "server_ids": list(self.server_ids),
            "scope": self.scope,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "enabled": self.enabled,
            "expired": self.expired,
            "active": self.active,
            "created_by": self.created_by,
            "rotated_from": self.rotated_from,
            "grace_ends_at": self.grace_ends_at,
        }
        if include_token:
            data["token"] = self.token_raw
        return data


class TokenStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> TokenRecord:
        return TokenRecord(
            id=row["id"],
            name=row["name"],
            token_hash=row["token_hash"],
            prefix=row["prefix"],
            server_ids=json.loads(row["server_ids"] or "[]"),
            scope=row["scope"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            last_used_at=row["last_used_at"],
            enabled=bool(row["enabled"]),
            token_raw="",
            created_by=row["created_by"],
            rotated_from=row["rotated_from"],
            grace_ends_at=row["grace_ends_at"],
        )

    def create_token(
        self,
        *,
        name: str,
        server_ids: Sequence[str],
        scope: str,
        expires_in_days: int | None = None,
        expires_at: str | None = None,
        created_by: str | None = None,
    ) -> tuple[TokenRecord, str]:
        """新しいトークンを発行する。生トークン文字列をタプルで一緒に返す (一度きり表示用)。"""
        raw = generate_token()
        record = self.import_token(
            name=name,
            raw=raw,
            server_ids=server_ids,
            scope=scope,
            expires_in_days=expires_in_days,
            expires_at=expires_at,
            created_by=created_by,
            store_raw=True,
        )
        record.token_raw = raw
        return record, raw

    def import_token(
        self,
        *,
        name: str,
        raw: str,
        server_ids: Sequence[str],
        scope: str,
        expires_in_days: int | None = None,
        expires_at: str | None = None,
        created_by: str | None = None,
        store_raw: bool = False,
    ) -> TokenRecord:
        normalized = sorted({str(sid) for sid in server_ids})
        if not normalized:
            raise ValueError("server_ids は1つ以上指定してください")
        for _ in range(5):
            token_id = new_token_id()
            try:
                with self._lock, self._connect() as conn:
                    conn.execute(
                        "INSERT INTO tokens "
                        "(id, name, token_raw, token_hash, prefix, server_ids, scope, "
                        "created_at, expires_at, last_used_at, enabled, created_by) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                        (
                            token_id,
                            name,
                            raw if store_raw else "",
                            hash_token(raw),
                            token_prefix(raw),
                            json.dumps(normalized),
                            scope,
                            now_iso(),
                            expires_at or expiry_iso(expires_in_days),
                            None,
                            created_by,
                        ),
                    )
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise RuntimeError("トークンの登録に失敗しました")
        record = self.get_token(token_id)
        if record is None:
            raise RuntimeError("トークンの登録に失敗しました")
        if store_raw:
            record.token_raw = raw
        return record

    def list_tokens(self, include_disabled: bool = True) -> list[TokenRecord]:
        query = "SELECT * FROM tokens"
        if not include_disabled:
            query += " WHERE enabled = 1"
        query += " ORDER BY created_at DESC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_token(self, token_id: str) -> TokenRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE id = ?", (token_id,)).fetchone()
        if row is None:
            return None
        rec = self._row_to_record(row)
        rec.token_raw = row["token_raw"]
        return rec

    def get_by_raw(self, raw: str) -> TokenRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_hash = ?", (hash_token(raw),)).fetchone()
        if row is None:
            return None
        rec = self._row_to_record(row)
        rec.token_raw = raw
        return rec

    def revoke_token(self, token_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("UPDATE tokens SET enabled = 0 WHERE id = ? AND enabled = 1", (token_id,))
            return cur.rowcount > 0

    def delete_token(self, token_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
            return cur.rowcount > 0

    def touch_last_used(self, token_id: str) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute("UPDATE tokens SET last_used_at = ? WHERE id = ?", (now_iso(), token_id))
        except sqlite3.Error:
            pass

    def find_token_for_server(self, server_id: str, scope: str | None = None) -> TokenRecord | None:
        """指定サーバーで利用可能な最新の有効トークンを返す。"*" は全サーバーを意味する。"""
        with self._lock, self._connect() as conn:
            query = "SELECT * FROM tokens WHERE enabled = 1"
            clauses: list[str] = []
            params: list[Any] = []
            if scope is not None:
                clauses.append("scope = ?")
                params.append(scope)
            if clauses:
                query += " AND " + " AND ".join(clauses)
            query += " ORDER BY created_at DESC"
            rows = conn.execute(query, params).fetchall()
        # JSONをパーサーして正確にserver_idが一致するものを探す
        for row in rows:
            try:
                server_ids = json.loads(row["server_ids"])
            except (json.JSONDecodeError, TypeError):
                continue
            if server_id in server_ids or "*" in server_ids:
                record = self._row_to_record(row)
                record.token_raw = row["token_raw"]
                return record
        return None

    def rotate_token(
        self,
        old_token_id: str,
        *,
        grace_period_days: int = 7,
        rotated_by: str | None = None,
        expires_in_days: int | None = None,
    ) -> TokenRecord:
        """トークンをローテーションする。

        古いトークンはgrace_period_daysの間有効（グラ期間）、
        新しいトークンを作成して返す。
        """
        old_record = self.get_token(old_token_id)
        if old_record is None:
            raise ValueError(f"トークンが見つかりません: {old_token_id}")
        if not old_record.enabled:
            raise ValueError(f"トークンは既に無効です: {old_token_id}")

        # 新しいトークンを生成
        rotation_id = "rot_" + secrets.token_hex(8)
        new_token_id = new_token_id()
        raw = generate_token()
        token_hash = hash_token(raw)
        prefix = token_prefix(raw)
        now = now_iso()
        grace_ends = expiry_iso(grace_period_days)
        new_expires = expiry_iso(expires_in_days) if expires_in_days else None

        with self._lock, self._connect() as conn:
            # 新しいトークンを登録
            for _ in range(5):
                try:
                    conn.execute(
                        """
                        INSERT INTO tokens
                        (id, name, token_raw, token_hash, prefix, server_ids, scope,
                         created_at, expires_at, enabled, created_by, rotated_from, grace_ends_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, NULL, NULL)
                        """,
                        (
                            new_token_id,
                            old_record.name,
                            raw,
                            token_hash,
                            prefix,
                            json.dumps(old_record.server_ids),
                            old_record.scope,
                            now,
                            new_expires,
                            rotated_by,
                        ),
                    )
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise RuntimeError("トークンローテーションに失敗しました")

            # 古いトークンのgrace_ends_atを設定
            conn.execute(
                "UPDATE tokens SET grace_ends_at = ? WHERE id = ?",
                (grace_ends, old_token_id),
            )

            # ローテーション履歴を記録
            conn.execute(
                """
                INSERT INTO token_rotations
                (id, old_token_id, new_token_id, rotated_at, grace_ends_at, rotated_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (rotation_id, old_token_id, new_token_id, now, grace_ends, rotated_by),
            )

        new_record = self.get_token(new_token_id)
        if new_record is None:
            raise RuntimeError("トークンローテーション後の取得に失敗しました")
        new_record.token_raw = raw
        return new_record

    def get_rotation_history(self, token_id: str) -> list[dict]:
        """トークンのローテーション履歴を取得する。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM token_rotations
                WHERE old_token_id = ? OR new_token_id = ?
                ORDER BY rotated_at DESC
                """,
                (token_id, token_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def cleanup_expired_grace_periods(self) -> int:
        """グラ期間を経過した古いトークンを無効にする。"""
        now = now_iso()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE tokens SET enabled = 0
                WHERE enabled = 1 AND grace_ends_at IS NOT NULL AND grace_ends_at < ?
                """,
                (now,),
            )
            return cur.rowcount

    def is_in_grace_period(self, token_id: str) -> bool:
        """トークンがグラ期間中か確認する。"""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT grace_ends_at FROM tokens WHERE id = ?",
                (token_id,),
            ).fetchone()
        if row is None or row["grace_ends_at"] is None:
            return False
        return not is_expired(row["grace_ends_at"])
