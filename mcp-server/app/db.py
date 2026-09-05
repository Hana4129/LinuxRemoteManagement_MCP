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

_SCHEMA_TABLES = """
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
    ,principal_id TEXT
);

CREATE TABLE IF NOT EXISTS principals (
    id            TEXT PRIMARY KEY,
    subject       TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    principal_id  TEXT NOT NULL,
    server_id     TEXT NOT NULL,
    scope         TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (principal_id, server_id, scope),
    FOREIGN KEY (principal_id) REFERENCES principals(id)
);

CREATE TABLE IF NOT EXISTS agent_credentials (
    id            TEXT PRIMARY KEY,
    server_id     TEXT NOT NULL,
    name          TEXT NOT NULL,
    agent_token_id TEXT NOT NULL DEFAULT '',
    token_raw     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1,
    agent_sync_state TEXT NOT NULL DEFAULT 'synced'
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
"""

_SCHEMA_INDEXES = """
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
    principal_id: str | None = None

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
            "principal_id": self.principal_id,
        }
        if include_token:
            data["token"] = self.token_raw
        return data


@dataclass
class AgentCredential:
    id: str
    server_id: str
    name: str
    agent_token_id: str
    token_raw: str
    created_at: str
    expires_at: str | None
    enabled: bool
    agent_sync_state: str = "synced"

    @property
    def active(self) -> bool:
        return self.enabled and not is_expired(self.expires_at)

    @property
    def server_ids(self) -> list[str]:
        return [self.server_id]

    @property
    def scope(self) -> str:
        return "operator"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "agent_token_id": self.agent_token_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "enabled": self.enabled,
            "active": self.active,
            "agent_sync_state": self.agent_sync_state,
        }


class TokenStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA_TABLES)
            self._migrate(conn)
            conn.executescript(_SCHEMA_INDEXES)
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """既存DBに対して必要なカラムを追加するマイグレーション。"""
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(tokens)")}
        if "rotated_from" not in existing:
            conn.execute("ALTER TABLE tokens ADD COLUMN rotated_from TEXT")
        if "grace_ends_at" not in existing:
            conn.execute("ALTER TABLE tokens ADD COLUMN grace_ends_at TEXT")
        if "principal_id" not in existing:
            conn.execute("ALTER TABLE tokens ADD COLUMN principal_id TEXT")
        credential_columns = {row["name"] for row in conn.execute("PRAGMA table_info(agent_credentials)")}
        if credential_columns and "agent_token_id" not in credential_columns:
            conn.execute("ALTER TABLE agent_credentials ADD COLUMN agent_token_id TEXT NOT NULL DEFAULT ''")
        if credential_columns and "agent_sync_state" not in credential_columns:
            conn.execute("ALTER TABLE agent_credentials ADD COLUMN agent_sync_state TEXT NOT NULL DEFAULT 'synced'")

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
            principal_id=row["principal_id"],
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
        principal_id: str | None = None,
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
            principal_id=principal_id,
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
        principal_id: str | None = None,
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
                        "created_at, expires_at, last_used_at, enabled, created_by, principal_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
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
                            principal_id,
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

    def grant_permission(self, principal_id: str, server_id: str, scope: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO permissions (principal_id, server_id, scope, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(principal_id, server_id, scope) DO UPDATE SET enabled=1",
                (principal_id, server_id, scope, now_iso()),
            )

    def revoke_permission(self, principal_id: str, server_id: str, scope: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE permissions SET enabled=0 WHERE principal_id=? AND server_id=? AND scope=? AND enabled=1",
                (principal_id, server_id, scope),
            )
            return cur.rowcount > 0

    def has_permission(self, principal_id: str, server_id: str, scope: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM permissions WHERE principal_id=? AND enabled=1 "
                "AND (server_id=? OR server_id='*') AND scope=? LIMIT 1",
                (principal_id, server_id, scope),
            ).fetchone()
        return row is not None

    def principal_active(self, principal_id: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT 1 FROM principals WHERE id=? AND enabled=1", (principal_id,)).fetchone()
        return row is not None

    def create_agent_credential(
        self, server_id: str, name: str, raw: str, agent_token_id: str = "", expires_in_days: int | None = None
    ) -> AgentCredential:
        credential_id = "agt_" + secrets.token_hex(8)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO agent_credentials (id, server_id, name, agent_token_id, token_raw, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (credential_id, server_id, name, agent_token_id, raw, now_iso(), expiry_iso(expires_in_days)),
            )
        return self.get_agent_credential(credential_id)  # type: ignore[return-value]

    def get_agent_credential(self, credential_id: str) -> AgentCredential | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM agent_credentials WHERE id=?", (credential_id,)).fetchone()
        return self._row_to_agent_credential(row) if row else None

    def find_agent_credential(self, server_id: str) -> AgentCredential | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM agent_credentials WHERE server_id=? AND enabled=1 "
                "ORDER BY created_at DESC LIMIT 1",
                (server_id,),
            ).fetchone()
        credential = self._row_to_agent_credential(row) if row else None
        return credential if credential and credential.active else None

    def list_agent_credentials(self) -> list[AgentCredential]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM agent_credentials ORDER BY created_at DESC").fetchall()
        return [self._row_to_agent_credential(row) for row in rows]

    def revoke_agent_credential(self, credential_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("UPDATE agent_credentials SET enabled=0 WHERE id=? AND enabled=1", (credential_id,))
            return cur.rowcount > 0

    def set_agent_credential_sync_state(self, credential_id: str, state: str) -> None:
        """Agent失効同期の状態を更新する (synced / pending / skipped)。"""
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE agent_credentials SET agent_sync_state=? WHERE id=?", (state, credential_id))

    def list_pending_revocation_syncs(self) -> list[AgentCredential]:
        """Agentへの失効同期が未完了 (pending) のcredential一覧を返す。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_credentials "
                "WHERE enabled=0 AND agent_sync_state='pending' AND agent_token_id<>'' "
                "ORDER BY created_at ASC"
            ).fetchall()
        return [self._row_to_agent_credential(row) for row in rows]

    @staticmethod
    def _row_to_agent_credential(row: sqlite3.Row) -> AgentCredential:
        keys = set(row.keys())
        return AgentCredential(
            id=row["id"], server_id=row["server_id"], name=row["name"], agent_token_id=row["agent_token_id"], token_raw=row["token_raw"],
            created_at=row["created_at"], expires_at=row["expires_at"], enabled=bool(row["enabled"]),
            agent_sync_state=row["agent_sync_state"] if "agent_sync_state" in keys else "synced",
        )

    def list_permissions(self, principal_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT principal_id, server_id, scope, enabled, created_at FROM permissions"
        params: tuple[str, ...] = ()
        if principal_id:
            query += " WHERE principal_id=?"
            params = (principal_id,)
        with self._lock, self._connect() as conn:
            return [dict(row) for row in conn.execute(query + " ORDER BY principal_id, server_id, scope", params)]

    def create_principal(self, subject: str, display_name: str, role: str = "viewer") -> dict[str, Any]:
        principal_id = "prn_" + secrets.token_hex(8)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO principals (id, subject, display_name, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (principal_id, subject, display_name, role, now_iso()),
            )
        return self.get_principal(principal_id) or {}

    def get_principal(self, principal_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM principals WHERE id=?", (principal_id,)).fetchone()
        return dict(row) if row else None

    def get_principal_by_subject(self, subject: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM principals WHERE subject=? AND enabled=1", (subject,)
            ).fetchone()
        return dict(row) if row else None

    def list_principals(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM principals ORDER BY created_at")]

    def disable_principal(self, principal_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("UPDATE principals SET enabled=0 WHERE id=? AND enabled=1", (principal_id,))
            conn.execute("UPDATE tokens SET enabled=0 WHERE principal_id=?", (principal_id,))
            conn.execute("UPDATE permissions SET enabled=0 WHERE principal_id=?", (principal_id,))
            return cur.rowcount > 0

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
                         created_at, expires_at, enabled, created_by, rotated_from, grace_ends_at, principal_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, NULL, NULL, ?)
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
                            old_record.principal_id,
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
