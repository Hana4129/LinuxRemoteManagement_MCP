"""ApprovalStore (approvals.py) の単体テスト。"""
from __future__ import annotations

import sqlite3

import pytest

from app.approvals import ApprovalError, ApprovalStore


def test_request_creates_pending(approvals: ApprovalStore):
    rec = approvals.request(server_id="dev-web-01", service="nginx", reason="メモリ不足", requested_by="mcp")
    assert rec.id.startswith("apr_")
    assert rec.status == "pending"
    assert rec.server_id == "dev-web-01"
    assert rec.service == "nginx"
    assert rec.requested_by == "mcp"
    assert rec.approved_at is None and rec.executed_at is None
    fetched = approvals.get(rec.id)
    assert fetched is not None and fetched.status == "pending"


def test_request_requires_server_and_service(approvals: ApprovalStore):
    with pytest.raises(ApprovalError):
        approvals.request(server_id="", service="nginx")
    with pytest.raises(ApprovalError):
        approvals.request(server_id="dev-web-01", service="")


def test_approve_pending_to_approved(approvals: ApprovalStore):
    rec = approvals.request(server_id="dev-web-01", service="nginx")
    approved = approvals.approve(rec.id, approver="運用者A", ttl_minutes=30)
    assert approved.status == "approved"
    assert approved.approver == "運用者A"
    assert approved.approved_at is not None
    assert approved.expires_at is not None  # ttl_minutes=30 で失効時刻が設定される


def test_reject_pending_to_rejected(approvals: ApprovalStore):
    rec = approvals.request(server_id="dev-web-01", service="nginx")
    rejected = approvals.reject(rec.id, approver="運用者B")
    assert rejected.status == "rejected"
    # rejected は消費できない
    with pytest.raises(ApprovalError):
        approvals.consume(rec.id)


def test_consume_is_one_time(approvals: ApprovalStore):
    rec = approvals.request(server_id="dev-web-01", service="nginx")
    approvals.approve(rec.id, ttl_minutes=15)
    executed = approvals.consume(rec.id)
    assert executed.status == "executed"
    assert executed.executed_at is not None
    # 2回目は失敗 (1回限り)
    with pytest.raises(ApprovalError):
        approvals.consume(rec.id)


def test_consume_pending_is_rejected(approvals: ApprovalStore):
    rec = approvals.request(server_id="dev-web-01", service="nginx")
    with pytest.raises(ApprovalError):
        approvals.consume(rec.id)


def test_consume_expired_approval_is_rejected(approvals: ApprovalStore):
    rec = approvals.request(server_id="dev-web-01", service="nginx")
    approvals.approve(rec.id, ttl_minutes=15)
    # expires_at を過去に書き換えて期限切れを再現する
    with sqlite3.connect(approvals.db_path) as conn:
        conn.execute("UPDATE approvals SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (rec.id,))
    with pytest.raises(ApprovalError, match="有効期限"):
        approvals.consume(rec.id)
    # レコード自体は approved のまま (消費されていない)
    assert approvals.get(rec.id).status == "approved"


def test_double_approve_is_rejected(approvals: ApprovalStore):
    rec = approvals.request(server_id="dev-web-01", service="nginx")
    approvals.approve(rec.id)
    with pytest.raises(ApprovalError):
        approvals.approve(rec.id)


def test_list_newest_first_and_delete(approvals: ApprovalStore):
    r1 = approvals.request(server_id="dev-web-01", service="nginx")
    r2 = approvals.request(server_id="dev-db-01", service="docker")
    listed = approvals.list()
    assert [r.id for r in listed] == [r2.id, r1.id]  # 新しい順
    assert approvals.delete(r1.id) is True
    assert approvals.delete(r1.id) is False
    assert approvals.get(r1.id) is None


def test_get_unknown_returns_none(approvals: ApprovalStore):
    assert approvals.get("apr_nonexistent") is None
