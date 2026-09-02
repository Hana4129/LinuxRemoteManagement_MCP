"""テスト共通フィクスチャ。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.approvals import ApprovalStore
from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig
from app.db import TokenStore
from app.mcp_audit import McpAudit


@pytest.fixture()
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def app_config(tmp_dir: Path) -> AppConfig:
    """単一サーバー (dev-web-01) を持つテスト用設定。"""
    return AppConfig(
        config_path=tmp_dir / "config.yml",
        servers=(
            ServerConfig(id="dev-web-01", name="Dev Web 01", url="http://127.0.0.1:1", env="development"),
            ServerConfig(id="dev-db-01", name="Dev DB 01", url="http://127.0.0.1:2", env="development"),
        ),
        agent=AgentConfig(timeout_seconds=2.0, tls_verify=False),
        console=ConsoleConfig(data_dir=str(tmp_dir), require_approval=True, approval_ttl_minutes=15, mcp_audit=True),
    )


@pytest.fixture()
def store(tmp_dir: Path) -> TokenStore:
    return TokenStore(tmp_dir / "tokens.db")


@pytest.fixture()
def approvals(tmp_dir: Path) -> ApprovalStore:
    return ApprovalStore(tmp_dir / "approvals.db")


@pytest.fixture()
def audit(tmp_dir: Path) -> McpAudit:
    return McpAudit(tmp_dir / "mcp_audit.jsonl")


def tool_json(result) -> dict:
    """FastMCP の ToolResult からJSONを取り出す。"""
    return json.loads(result.content[0].text)
