"""管理コンソール REST API のテスト (meta / approvals / nodes)。"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig
from app.main import create_app


@pytest.fixture()
def client(app_config, store):
    # 全サーバーを対象とするワイルドカードトークン (無いとノード状況が no_token になる)
    store.create_token(name="test-token", server_ids=["*"], scope="readonly")
    app = create_app(app_config, store=store)
    return TestClient(app), app


def test_meta(client):
    http, app = client
    res = http.get("/api/meta")
    assert res.status_code == 200
    body = res.json()
    assert any(s["id"] == "dev-web-01" for s in body["servers"])


def test_approvals_empty_list(client):
    http, _ = client
    res = http.get("/api/approvals")
    assert res.status_code == 200
    assert res.json()["approvals"] == []


def test_create_and_approve_via_api(client):
    """承認フロー: pending 作成 → APIで承認 → approved。監査ログにも記録される。"""
    http, app = client
    rec = app.state.approvals.request(server_id="dev-web-01", service="nginx", requested_by="mcp")

    res = http.post(f"/api/approvals/{rec.id}/approve", json={"approver": "運用者A", "ttl_minutes": 30})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "approved"
    assert body["approver"] == "運用者A"
    assert body["expires_at"] is not None

    # 一覧にも反映される
    listed = http.get("/api/approvals").json()["approvals"]
    assert [r["id"] for r in listed] == [rec.id]

    # 監査ログに承認操作が記録される
    entries = app.state.audit.read_entries()
    approve_entries = [e for e in entries if e["action"] == "approve_restart"]
    assert len(approve_entries) == 1
    assert approve_entries[0]["actor"] == "console:運用者A"
    assert approve_entries[0]["params"]["approval_id"] == rec.id


def test_approve_unknown_returns_404(client):
    http, _ = client
    res = http.post("/api/approvals/apr_missing/approve", json={"approver": "x"})
    assert res.status_code == 404


def test_double_approve_returns_409(client):
    http, app = client
    rec = app.state.approvals.request(server_id="dev-web-01", service="nginx")
    assert http.post(f"/api/approvals/{rec.id}/approve", json={}).status_code == 200
    res = http.post(f"/api/approvals/{rec.id}/approve", json={})
    assert res.status_code == 409


def test_reject_flow(client):
    http, app = client
    rec = app.state.approvals.request(server_id="dev-db-01", service="docker")
    res = http.post(f"/api/approvals/{rec.id}/reject", json={"approver": "運用者B"})
    assert res.status_code == 200
    assert res.json()["status"] == "rejected"

    # rejected は再度 reject できない
    assert http.post(f"/api/approvals/{rec.id}/reject", json={}).status_code == 409
    # rejected は approve もできない
    assert http.post(f"/api/approvals/{rec.id}/approve", json={}).status_code == 409


def test_delete_approval(client):
    http, app = client
    rec = app.state.approvals.request(server_id="dev-web-01", service="nginx")
    assert http.delete(f"/api/approvals/{rec.id}").status_code == 200
    assert http.delete(f"/api/approvals/{rec.id}").status_code == 404


def test_approvals_disabled_returns_503(tmp_dir: Path, store):
    """require_approval=False の場合、承認APIは503を返す。"""
    config = AppConfig(
        config_path=tmp_dir / "config.yml",
        servers=(
            ServerConfig(id="dev-web-01", name="Dev Web 01", url="http://127.0.0.1:1", env="development"),
            ServerConfig(id="dev-db-01", name="Dev DB 01", url="http://127.0.0.1:2", env="development"),
        ),
        agent=AgentConfig(timeout_seconds=2.0, tls_verify=False),
        console=ConsoleConfig(
            data_dir=str(tmp_dir / "no-approval"),
            require_approval=False,
            mcp_audit=True,
            mcp_http=False,
        ),
    )
    app = create_app(config, store=store)
    http = TestClient(app)
    res = http.get("/api/approvals")
    assert res.status_code == 503


def test_nodes_reports_unreachable(client):
    """到達不能なAgentは not_responding/unreachable として集計される。"""
    http, _ = client
    res = http.get("/api/nodes")
    assert res.status_code == 200
    body = res.json()
    assert body["summary"]["total"] == 2
    statuses = {n["id"]: n["install_status"] for n in body["nodes"]}
    assert statuses["dev-web-01"] in {"not_responding", "unreachable"}
    assert body["summary"]["problems"] == 2
