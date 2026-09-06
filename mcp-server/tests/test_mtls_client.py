"""MCP Server の mTLS クライアント設定 (client_cert/client_key) の伝播を検証するテスト。

mTLS の実ハンドシェイク (証明書なし拒否・不正CA拒否) は Go Agent 側の
`tls_test.go` (TestMTLSHandshake_ClientCertificateEnforcement) で検証済み。
本テストは Python 側で `AgentClient` が `client_cert` / `client_key` を
httpx.AsyncClient の `cert` 引数として正しく渡すことをモックで確認する。
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from app.agent_client import AgentClient
from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig
from app.db import TokenStore


def _config(tmp_path, agent: AgentConfig) -> AppConfig:
    return AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(ServerConfig(id="dev", name="Dev", url="https://127.0.0.1:8443", env="development"),),
        agent=agent,
        console=ConsoleConfig(data_dir=str(tmp_path), auth_required=False),
    )


def test_agent_client_passes_client_cert_to_httpx(tmp_path):
    """client_cert/client_key が set 済みなら httpx cert=(cert, key) として渡る。"""
    cfg = _config(
        tmp_path,
        AgentConfig(
            timeout_seconds=5.0, tls_verify=False,
            client_cert="/certs/client.crt", client_key="/certs/client.key",
        ),
    )
    store = TokenStore(tmp_path / "tokens.db")
    with patch("app.agent_client.httpx.AsyncClient") as mock_client:
        mock_client.return_value.aclose = AsyncMock()
        client = AgentClient(cfg, store)
        asyncio.run(client.aclose())
    mock_client.assert_called_once()
    kwargs = mock_client.call_args.kwargs
    assert kwargs["cert"] == ("/certs/client.crt", "/certs/client.key")
    assert kwargs["verify"] is False
    assert kwargs["timeout"].connect == 5.0


def test_agent_client_passes_none_when_cert_unset(tmp_path):
    """client_cert/client_key 未設定なら cert=None (通常TLS/平文) のまま。"""
    cfg = _config(tmp_path, AgentConfig(timeout_seconds=5.0, tls_verify=True))
    store = TokenStore(tmp_path / "tokens.db")
    with patch("app.agent_client.httpx.AsyncClient") as mock_client:
        mock_client.return_value.aclose = AsyncMock()
        client = AgentClient(cfg, store)
        asyncio.run(client.aclose())
    kwargs = mock_client.call_args.kwargs
    assert kwargs["cert"] is None
    assert kwargs["verify"] is True


def test_agent_client_requires_pair_cert_key(tmp_path):
    """client_cert のみ指定 (client_key なし) の場合は cert=None のまま。"""
    cfg = _config(
        tmp_path,
        AgentConfig(timeout_seconds=5.0, tls_verify=False, client_cert="/certs/client.crt", client_key=""),
    )
    store = TokenStore(tmp_path / "tokens.db")
    with patch("app.agent_client.httpx.AsyncClient") as mock_client:
        mock_client.return_value.aclose = AsyncMock()
        client = AgentClient(cfg, store)
        asyncio.run(client.aclose())
    kwargs = mock_client.call_args.kwargs
    assert kwargs["cert"] is None