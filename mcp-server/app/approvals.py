"""Human Approval (承認) ストア。

破壊的操作 (restart_service など) を MCP が実行する前に、人間の承認を必須化する。
設計書 §28 Level 3 の "Human approval" に対応。

フロー:
  1. MCP tool ``request_restart_approval`` が承認要求を作成 (status=pending)
  2. 人間が管理コンソール (``POST /api/approvals/{id}/approve``) で承認
  3. MCP tool ``restart_service(approval_id=...)`` が承認を消費して実行
     - 承認は1回限り (実行で consumed)
     - 承認後 ttl_minutes を過ぎた承認は無効 (expired)
     - pending / rejected / expired は実行不可
"""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,
    server_id    TEXT NOT NULL,
    service      TEXT NOT NULL,
    reason       TEXT,
    status       TEXT NOT NULL,          -- pending | approved | rejected | executed
    requested_by TEXT,
    requested_at TEXT NOT NULL,
    approver     TEXT,
    approved_at  TEXT,
    expires_at   TEXT,
    executed_at  TEXT
);
"""

VALID_TRANSITIONS = {"approve": ("pending",), "reject": ("pending",), "consume": ("approved",)}


class ApprovalError(Exception):
    """承認操作の失敗 (状態遷移違反・期限切れ等)。"""


class ApprovalNotFoundError(ApprovalError):
    """指定IDの承認が存在しない (APIでは404として扱う)。"""


@dataclass
class ApprovalRecord:
    id: str
    server_id: str
    service: str
    reason: str
    status: str
    requested_by: str | None
    requested_at: str
    approver: str | None = None
    approved_at: str | None = None
    expires_at: str | None = None
    executed_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "server_id": self.server_id,
            "service": self.service,
            "reason": self.reason,
            "status": self.status,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "approver": self.approver,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "executed_at": self.executed_at,
        }


def new_approval_id() -> str:
    return "apr_" + secrets.token_hex(8)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class ApprovalStore:
    """SQLite バックエンドの承認ストア。"""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            id=row["id"],
            server_id=row["server_id"],
            service=row["service"],
            reason=row["reason"] or "",
            status=row["status"],
            requested_by=row["requested_by"],
            requested_at=row["requested_at"],
            approver=row["approver"],
            approved_at=row["approved_at"],
            expires_at=row["expires_at"],
            executed_at=row["executed_at"],
        )

    def request(
        self, *, server_id: str, service: str, reason: str = "", requested_by: str = "mcp", ttl_minutes: int = 15
    ) -> ApprovalRecord:
        """承認要求を新規作成する (status=pending)。"""
        if not server_id or not service:
            raise ApprovalError("server_id / service は必須です")
        rec = ApprovalRecord(
            id=new_approval_id(),
            server_id=server_id,
            service=service,
            reason=str(reason or "")[:500],
            status="pending",
            requested_by=requested_by,
            requested_at=now_iso(),
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO approvals (id, server_id, service, reason, status, requested_by, requested_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rec.id, rec.server_id, rec.service, rec.reason, rec.status, rec.requested_by, rec.requested_at),
            )
        return rec

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def list(self, limit: int = 100) -> list[ApprovalRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM approvals ORDER BY requested_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_record(row) for row in rows]

    def _transition(self, approval_id: str, action: str, *, approver: str = "", ttl_minutes: int = 0) -> ApprovalRecord:
        """状態遷移 (approve/reject/consume) を排他制御下で実行する。"""
        if action not in VALID_TRANSITIONS:
            raise ApprovalError(f"未知の操作: {action}")
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            if row is None:
                raise ApprovalNotFoundError(f"承認が見つかりません: {approval_id}")
            rec = self._row_to_record(row)
            if rec.status not in VALID_TRANSITIONS[action]:
                raise ApprovalError(f"承認の状態が不正です (status={rec.status}, 操作={action})")
            ts = now_iso()
            if action == "approve":
                expires = (
                    datetime.now(timezone.utc) + timedelta(minutes=max(0, ttl_minutes))
                ).isoformat(timespec="seconds")
                conn.execute(
                    "UPDATE approvals SET status='approved', approver=?, approved_at=?, expires_at=? WHERE id=?",
                    (approver or "console", ts, expires, approval_id),
                )
            elif action == "reject":
                conn.execute(
                    "UPDATE approvals SET status='rejected', approver=?, approved_at=? WHERE id=?",
                    (approver or "console", ts, approval_id),
                )
            else:  # consume: approved → executed (1回限り)
                self._ensure_not_expired(rec)
                cur = conn.execute(
                    "UPDATE approvals SET status='executed', executed_at=? WHERE id=? AND status='approved'",
                    (ts, approval_id),
                )
                if cur.rowcount != 1:
                    raise ApprovalError("承認を消費できませんでした (競合または状態不整合)")
        return self.get(approval_id)  # type: ignore[return-value]

    def approve(self, approval_id: str, *, approver: str = "console", ttl_minutes: int = 15) -> ApprovalRecord:
        """pending の承認を承認する。承認後 ttl_minutes で失効する。"""
        return self._transition(approval_id, "approve", approver=approver, ttl_minutes=ttl_minutes)

    def reject(self, approval_id: str, *, approver: str = "console") -> ApprovalRecord:
        """pending の承認を却下する。"""
        return self._transition(approval_id, "reject", approver=approver)

    def consume(self, approval_id: str) -> ApprovalRecord:
        """approved の承認を1回限り消費する (executed にする)。期限切れは拒否。"""
        return self._transition(approval_id, "consume")

    @staticmethod
    def _ensure_not_expired(rec: ApprovalRecord) -> ApprovalRecord:
        if rec.expires_at:
            try:
                exp = datetime.fromisoformat(rec.expires_at)
            except ValueError as exc:
                raise ApprovalError(f"承認の有効期限が不正です: {rec.expires_at}") from exc
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= exp:
                raise ApprovalError(f"承認の有効期限が切れています (expires_at={rec.expires_at})")
        return rec

    def delete(self, approval_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM approvals WHERE id = ?", (approval_id,))
            return cur.rowcount > 0

