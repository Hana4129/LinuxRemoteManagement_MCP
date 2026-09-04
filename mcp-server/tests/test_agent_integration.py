"""execute_command / write_file MCP Tools の統合テスト (実機Agent API契約の固定)。

モックAgent (tools/mock_agent.py) は実機 (Go) Agent と同じ API 契約を模倣する:
- POST /v1/execute: command は JSON ボディ、応答は execResult 形式
- POST /v1/files:   path は query パラメータ、content は JSON ボディ

背景: write_file が従来 path を JSON ボディで送信しており、実機 Agent では
400 (path required) になる不具合が実機試験で判明した。本テストで契約を固定し回帰を防ぐ。
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

_OP_RAW = "op-int-raw"
_RO_RAW = "ro-int-raw"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture()
def mock_agent():
    """モックAgentを空きポートで起動し、ベースURLを返す (operator+readonly両方を受け付ける)。"""
    port = _free_port()
    app = build_app(tokens=[_OP_RAW, _RO_RAW])
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


def _build_mcp(tmp_path, mock_agent_url: str, tokens: list[tuple[str, str, str]]):
    """指定トークン (name, raw, scope) を登録した MCP サーバーを組立てる。"""
    config = AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(ServerConfig(id="dev-web-01", name="Dev Web 01", url=mock_agent_url, env="development"),),
        agent=AgentConfig(timeout_seconds=5.0, tls_verify=False),
        console=ConsoleConfig(data_dir=str(tmp_path), require_approval=False, approval_ttl_minutes=15, mcp_audit=True),
    )
    store = TokenStore(tmp_path / "tokens.db")
    for name, raw, scope in tokens:
        store.import_token(name=name, raw=raw, server_ids=["dev-web-01"], scope=scope, store_raw=True)
    return build_mcp(config, store, ApprovalStore(tmp_path / "approvals.db"), McpAudit(tmp_path / "mcp_audit.jsonl"))


def call(mcp, name: str, arguments: dict) -> dict:
    """MCP Tool を in-memory Client 経由で呼び、JSONを返す。"""

    async def _inner() -> dict:
        async with Client(mcp) as client:
            result = await client.call_tool(name, arguments)
        return tool_json(result)

    return asyncio.run(_inner())


def test_execute_command_with_operator_token(e2e_op, mock_agent):
    """operator トークンで /v1/execute が実行される (command は JSON ボディ契約)。"""
    data = call(e2e_op, "execute_command", {"server": "dev-web-01", "command": "systemctl status nginx"})
    assert data["ok"] is True
    body = data["data"]
    assert body["command"] == "systemctl status nginx"
    assert body["exit_code"] == 0
    assert "systemctl status nginx" in body["stdout"]
    assert body["timed_out"] is False


def test_write_file_contract_query_path(e2e_op, mock_agent):
    """実機契約: path は query パラメータ、content は JSON ボディ。

    モックは query で受けた path を応答の path にそのまま返すため、
    クライアントが query で送信していること (修正後の契約) を検証できる。
    """
    data = call(e2e_op, "write_file", {"server": "dev-web-01", "path": "/var/tmp/app.conf", "content": "key=value\n"})
    assert data["ok"] is True
    body = data["data"]
    assert body["status"] == "written"
    assert body["path"] == "/var/tmp/app.conf"
    assert body["backup"] == "/var/tmp/app.conf.bak"


def test_execute_command_without_operator_token(tmp_path, mock_agent):
    """operator トークン未登録のサーバーでは client 側で no_token となる。"""
    mcp = _build_mcp(tmp_path, mock_agent, [("ro", _RO_RAW, "readonly")])
    data = call(mcp, "execute_command", {"server": "dev-web-01", "command": "ls"})
    assert data["ok"] is False
    assert data["error_kind"] == "no_token"


def test_write_file_without_operator_token(tmp_path, mock_agent):
    """operator トークン未登録のサーバーでは client 側で no_token となる。"""
    mcp = _build_mcp(tmp_path, mock_agent, [("ro", _RO_RAW, "readonly")])
    data = call(mcp, "write_file", {"server": "dev-web-01", "path": "/var/tmp/app.conf", "content": "x"})
    assert data["ok"] is False
    assert data["error_kind"] == "no_token"


@pytest.fixture()
def e2e_op(tmp_path, mock_agent):
    """operator トークンを1つ登録した MCP サーバー。"""
    return _build_mcp(tmp_path, mock_agent, [("op", _OP_RAW, "operator")])
