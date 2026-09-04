"""E2E テスト: FastMCP (in-memory Client) × モックAgent (uvicorn) × 承認フロー × 監査ログ。

Issue 13 (LINUX-14) 完了条件の検証:
- get_system_info / restart_service / read_file のE2E
- Human Approval (request → console承認 → 実行 → 1回限り消費)
- MCP監査ログ (actor=トークン名, action, server の記録)
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from types import SimpleNamespace

import pytest
import uvicorn
from fastmcp import Client

from app.approvals import ApprovalStore
from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig
from app.db import TokenStore
from app.mcp_audit import McpAudit
from app.mcp_server import build_mcp
from tools.mock_agent import build_app

from .conftest import tool_json

_READONLY_RAW = "ro-raw-token"
_OPERATOR_RAW = "op-raw-token"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture()
def mock_agent():
    """モックAgentを空きポートで起動し、ベースURLを返す (readonly+operator両方を受け付ける)。"""
    port = _free_port()
    app = build_app(tokens=[_READONLY_RAW, _OPERATOR_RAW])
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        pytest.fail("モックAgentの起動に失敗しました")
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture()
def e2e(tmp_path, mock_agent):
    """モックAgentに向いた MCP サーバー (トークン2種・承認ストア・監査ログ込み)。"""
    config = AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(
            ServerConfig(id="dev-web-01", name="Dev Web 01", url=mock_agent, env="development"),
            ServerConfig(id="dev-db-01", name="Dev DB 01", url=mock_agent, env="development"),
        ),
        agent=AgentConfig(timeout_seconds=5.0, tls_verify=False),
        console=ConsoleConfig(data_dir=str(tmp_path), require_approval=True, approval_ttl_minutes=15, mcp_audit=True),
    )
    store = TokenStore(tmp_path / "tokens.db")
    # readonlyトークンは1つで両サーバーをカバー (同一生トークンの二重登録は hash UNIQUE 違反)
    store.import_token(name="ro-both", raw=_READONLY_RAW, server_ids=["dev-web-01", "dev-db-01"], scope="readonly", store_raw=True)
    store.import_token(name="op-web", raw=_OPERATOR_RAW, server_ids=["dev-web-01"], scope="operator", store_raw=True)
    approvals = ApprovalStore(tmp_path / "approvals.db")
    audit = McpAudit(tmp_path / "mcp_audit.jsonl")
    mcp = build_mcp(config, store, approvals, audit)
    return SimpleNamespace(mcp=mcp, store=store, approvals=approvals, audit=audit)


def call(e2e, name: str, arguments: dict) -> dict:
    """MCP Tool を in-memory Client 経由で呼び、JSONを返す。"""

    async def _inner() -> dict:
        async with Client(e2e.mcp) as client:
            result = await client.call_tool(name, arguments)
        return tool_json(result)

    return asyncio.run(_inner())


def call_error(e2e, name: str, arguments: dict) -> Exception:
    """MCP Tool 呼び出しがエラーになることを確認する。"""

    async def _inner() -> Exception:
        async with Client(e2e.mcp) as client:
            try:
                await client.call_tool(name, arguments)
            except Exception as exc:  # noqa: BLE001
                return exc
        pytest.fail(f"{name} はエラーになる想定ですが成功しました")

    return asyncio.run(_inner())


# ---- 読み取り系ツール ----


def test_e2e_get_system_info(e2e):
    """完了条件: get_system_info がAgent経由でシステム情報を返す。"""
    data = call(e2e, "get_system_info", {"server": "dev-web-01"})
    assert data["ok"] is True
    assert data["data"]["os"] == "Ubuntu 24.04.1 LTS"
    assert data["data"]["kernel"] == "6.8.0-45-generic"
    assert data["data"]["uptime_seconds"] > 0


def test_e2e_get_disk_usage(e2e):
    data = call(e2e, "get_disk_usage", {"server": "dev-web-01"})
    assert data["ok"] is True
    mounts = {fs["mount"] for fs in data["data"]["filesystems"]}
    assert "/" in mounts


def test_e2e_get_processes(e2e):
    data = call(e2e, "get_processes", {"server": "dev-web-01"})
    assert data["ok"] is True
    assert any(p["command"].startswith("nginx") for p in data["data"]["processes"])


def test_e2e_get_service_status_and_logs(e2e):
    status = call(e2e, "get_service_status", {"server": "dev-web-01", "service": "nginx"})
    assert status["ok"] is True
    assert status["data"]["active"] is True

    logs = call(e2e, "get_service_logs", {"server": "dev-web-01", "service": "nginx", "lines": 10})
    assert logs["ok"] is True
    assert logs["data"]["lines"]


def test_e2e_read_file_allowed(e2e):
    """完了条件: read_file が許可パスの内容を返す。"""
    data = call(e2e, "read_file", {"server": "dev-web-01", "path": "/etc/os-release"})
    assert data["ok"] is True
    assert "Ubuntu" in data["data"]["content"]


def test_e2e_read_file_denied(e2e):
    """Agent (403) が拒否したパスはエラーとして返る。"""
    data = call(e2e, "read_file", {"server": "dev-web-01", "path": "/etc/shadow"})
    assert data["ok"] is False
    assert data["error_kind"] == "auth"  # 401/403 → auth


def test_e2e_unknown_server_is_error(e2e):
    exc = call_error(e2e, "get_system_info", {"server": "no-such-server"})
    assert "未知のサーバーID" in str(exc)


def test_e2e_list_servers(e2e):
    data = call(e2e, "list_servers", {})
    ids = {s["id"] for s in data["servers"]}
    assert ids == {"dev-web-01", "dev-db-01"}


# ---- Human Approval フロー (restart_service) ----


def test_e2e_restart_requires_approval(e2e):
    """完了条件: approval_id なしの restart_service は approval_required。"""
    data = call(e2e, "restart_service", {"server": "dev-web-01", "service": "nginx"})
    assert data["ok"] is False
    assert data["error_kind"] == "approval_required"
    assert data["approval"]["status"] == "pending"
    assert data["approval"]["server_id"] == "dev-web-01"
    assert data["approval"]["service"] == "nginx"


def test_e2e_restart_full_approval_flow(e2e):
    """完了条件: request → 人間が承認 → 実行成功 → 承認は1回限り消費。"""
    req = call(e2e, "request_restart_approval", {"server": "dev-web-01", "service": "nginx", "reason": "E2E"})
    assert req["ok"] is True
    approval_id = req["data"]["id"]

    # 人間が管理コンソールで承認する操作相当
    e2e.approvals.approve(approval_id, approver="運用者", ttl_minutes=15)

    executed = call(e2e, "restart_service", {"server": "dev-web-01", "service": "nginx", "approval_id": approval_id})
    assert executed["ok"] is True
    assert executed["data"]["success"] is True
    assert executed["data"]["service"] == "nginx"

    # 同じ approval_id の再実行は拒否 (1回限り)
    replay = call(e2e, "restart_service", {"server": "dev-web-01", "service": "nginx", "approval_id": approval_id})
    assert replay["ok"] is False
    assert replay["error_kind"] == "approval_invalid"


def test_e2e_restart_mismatched_approval(e2e):
    """他サーバー向けの承認は一致チェックで拒否される。"""
    req = call(e2e, "request_restart_approval", {"server": "dev-db-01", "service": "nginx"})
    approval_id = req["data"]["id"]
    e2e.approvals.approve(approval_id, ttl_minutes=15)

    data = call(e2e, "restart_service", {"server": "dev-web-01", "service": "nginx", "approval_id": approval_id})
    assert data["ok"] is False
    assert data["error_kind"] == "approval_mismatch"


def test_e2e_restart_without_operator_token(e2e):
    """operatorトークンの無いサーバーでは、承認を消費せず no_token。"""
    req = call(e2e, "request_restart_approval", {"server": "dev-db-01", "service": "nginx"})
    approval_id = req["data"]["id"]
    e2e.approvals.approve(approval_id, ttl_minutes=15)

    data = call(e2e, "restart_service", {"server": "dev-db-01", "service": "nginx", "approval_id": approval_id})
    assert data["ok"] is False
    assert data["error_kind"] == "no_token"

    # 承認は消費されていない (approved のまま)
    rec = e2e.approvals.get(approval_id)
    assert rec is not None and rec.status == "approved"


# ---- MCP監査ログ ----


def test_e2e_audit_log_records_actor_and_action(e2e):
    """完了条件: Tool呼び出しが actor=トークン名 で監査ログに記録される。"""
    call(e2e, "get_system_info", {"server": "dev-web-01"})
    call(e2e, "restart_service", {"server": "dev-web-01", "service": "nginx"})  # approval_required (失敗も記録)

    entries = e2e.audit.read_entries()
    actions = {e["action"] for e in entries}
    assert "get_system_info" in actions
    assert "restart_service" in actions

    sys_entry = next(e for e in entries if e["action"] == "get_system_info")
    assert sys_entry["server"] == "dev-web-01"
    assert sys_entry["ok"] is True
    assert sys_entry["actor"].startswith("mcp:")  # actor はトークン名ベース
    assert _READONLY_RAW not in str(entries)  # 生トークンは記録しない

    restart_entry = next(e for e in entries if e["action"] == "restart_service")
    assert restart_entry["ok"] is False
    assert restart_entry["error_kind"] == "approval_required"
# ---- 複数ノード一括操作 ----


def test_e2e_get_status_all(e2e):
    """完了条件: 複数ノードを一括でシステム情報取得し、ノードごとに集約される。"""
    data = call(e2e, "get_status_all", {})
    assert data["ok"] is True
    assert data["summary"]["total"] == 2   # dev-web-01 + dev-db-01
    assert data["summary"]["ok"] == 2
    assert "dev-web-01" in data["results"]
    assert "dev-db-01" in data["results"]
    assert data["results"]["dev-web-01"]["ok"] is True


def test_e2e_get_status_all_selected_servers(e2e):
    """完了条件: servers 指定で対象ノードが絞り込まれる。"""
    data = call(e2e, "get_status_all", {"servers": ["dev-web-01"]})
    assert data["summary"]["total"] == 1
    assert "dev-web-01" in data["results"]
    assert "dev-db-01" not in data["results"]


def test_e2e_get_service_status_all(e2e):
    """完了条件: 複数ノードのサービス状態を一括取得できる。"""
    data = call(e2e, "get_service_status_all", {"service": "nginx"})
    assert data["summary"]["total"] == 2
    assert data["results"]["dev-web-01"]["ok"] is True
    assert data["results"]["dev-web-01"]["data"]["service"] == "nginx"


def test_e2e_get_service_status_all_missing_service(e2e):
    """完了条件: service 未指定は missing_service エラー。"""
    data = call(e2e, "get_service_status_all", {})
    assert data["ok"] is False
    assert data["error_kind"] == "missing_service"


def test_e2e_restart_service_all_requires_approval(e2e):
    """完了条件: approval_id なしの一括再起動は、各ノードで approval_required が返る。"""
    data = call(e2e, "restart_service_all", {"service": "nginx"})
    assert data["summary"]["total"] == 2
    assert data["summary"]["ok"] == 0
    assert data["summary"]["failed"] == 2
    for sid in ("dev-web-01", "dev-db-01"):
        res = data["results"][sid]
        assert res["ok"] is False
        assert res["error_kind"] in ("approval_required", "no_token")


def test_e2e_restart_service_all_with_approval(e2e):
    """完了条件: ノードごとの approval_id を渡すと一括再起動が実行される (dev-web-01 のみ operator トークンあり)。"""
    # dev-web-01 向け承認要求 → 承認
    req = call(e2e, "request_restart_approval", {"server": "dev-web-01", "service": "nginx"})
    approval_id = req["data"]["id"]
    e2e.approvals.approve(approval_id, approver="運用者", ttl_minutes=15)




    data = call(e2e, "restart_service_all", {"service": "nginx", "approval_id": f"dev-web-01={approval_id}"})
    assert data["results"]["dev-web-01"]["ok"] is True
    assert data["results"]["dev-web-01"]["data"]["success"] is True
    # dev-db-01 は operator トークンが無いため no_token
    assert data["results"]["dev-db-01"]["ok"] is False
