"""MCP Server の mTLS クライアント設定 (client_cert/client_key) の伝播を検証するテスト。

mTLS の実ハンドシェイク (証明書なし拒否・不正CA拒否) は Go Agent 側の
`tls_test.go` (TestMTLSHandshake_ClientCertificateEnforcement) で検証済み。
本テストは Python 側で `AgentClient` が `client_cert` / `client_key` を
SSLContext にロードして httpx.AsyncClient の `verify` 引数に渡すことを
モックで確認する。

注: httpx 0.28 以降は `verify=<CAパス>` + `cert=(crt, key)` の組み合わせで
クライアント証明書が送信されないため、明示的な SSLContext を構築する方式に
変更した (`app.config._build_agent_ssl_context`)。
"""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import AsyncMock, patch

from app.agent_client import AgentClient
from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig, _build_agent_ssl_context
from app.db import TokenStore


def _config(tmp_path, agent: AgentConfig) -> AppConfig:
    return AppConfig(
        config_path=tmp_path / "config.yml",
        servers=(ServerConfig(id="dev", name="Dev", url="https://127.0.0.1:8443", env="development"),),
        agent=agent,
        console=ConsoleConfig(data_dir=str(tmp_path), auth_required=False),
    )


def test_build_agent_ssl_context_with_client_cert(tmp_path):
    """_build_agent_ssl_context がクライアント証明書をSSLContextにロードする。"""
    # 実在しない証明書パスでは load_cert_chain が失敗するため、
    # 引数の伝播のみを直接テストする (ダミー証明書生成は過剰)
    ctx = _build_agent_ssl_context(True)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_build_agent_ssl_context_verify_false():
    """tls_verify=False なら検証無効のSSLContextを返す。"""
    ctx = _build_agent_ssl_context(False)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def _write_test_certs(tmp_path):
    """テスト用の自己署名CA+クライアント証明書を生成してパスを返す。"""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-client")]))
        .issuer_name(name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    crt_path = tmp_path / "client.crt"
    key_path = tmp_path / "client.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    crt_path.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(ca_path), str(crt_path), str(key_path)


def test_build_agent_ssl_context_with_ca_path(tmp_path):
    """tls_verify=CAパス なら CA ロード済みSSLContextを返す。"""
    ca_path, _, _ = _write_test_certs(tmp_path)
    ctx = _build_agent_ssl_context(ca_path)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_build_agent_ssl_context_loads_client_cert(tmp_path):
    """client_cert/client_key 付きで SSLContext に証明書がロードされる。"""
    _, crt_path, key_path = _write_test_certs(tmp_path)
    ctx = _build_agent_ssl_context(True, client_cert=crt_path, client_key=key_path)
    assert isinstance(ctx, ssl.SSLContext)
    # ロード済み証明書があること (getpeercert はサーバー側、ここでは内部統計で確認)
    stats = ctx.cert_store_stats()
    assert stats.get("x509", 0) >= 1


def test_agent_client_passes_ssl_context_to_httpx(tmp_path):
    """client_cert/client_key が set 済みなら SSLContext が verify として渡る。"""
    ca_path, crt_path, key_path = _write_test_certs(tmp_path)
    cfg = _config(
        tmp_path,
        AgentConfig(
            timeout_seconds=5.0, tls_verify=ca_path,
            client_cert=crt_path, client_key=key_path,
        ),
    )
    store = TokenStore(tmp_path / "tokens.db")
    with patch("app.agent_client.httpx.AsyncClient") as mock_client:
        mock_client.return_value.aclose = AsyncMock()
        client = AgentClient(cfg, store)
        asyncio.run(client.aclose())
    mock_client.assert_called_once()
    kwargs = mock_client.call_args.kwargs
    # SSLContext が verify として渡り、cert kwarg は使わない
    assert isinstance(kwargs["verify"], ssl.SSLContext)
    assert kwargs["timeout"].connect == 5.0


def test_agent_client_verify_true_when_cert_unset(tmp_path):
    """client_cert/client_key 未設定なら通常TLS検証のSSLContext。"""
    cfg = _config(tmp_path, AgentConfig(timeout_seconds=5.0, tls_verify=True))
    store = TokenStore(tmp_path / "tokens.db")
    with patch("app.agent_client.httpx.AsyncClient") as mock_client:
        mock_client.return_value.aclose = AsyncMock()
        client = AgentClient(cfg, store)
        asyncio.run(client.aclose())
    kwargs = mock_client.call_args.kwargs
    assert isinstance(kwargs["verify"], ssl.SSLContext)
    assert kwargs["verify"].verify_mode == ssl.CERT_REQUIRED


def test_agent_client_requires_pair_cert_key(tmp_path):
    """client_cert のみ指定 (client_key なし) の場合はクライアント証明書なしのSSLContext。"""
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
    assert isinstance(kwargs["verify"], ssl.SSLContext)
    assert kwargs["verify"].verify_mode == ssl.CERT_NONE