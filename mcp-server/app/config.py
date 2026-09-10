"""設定の読み込みと設定オブジェクト定義。

`config.yml` は以下の構造を期待する。

    console: { host, port, data_dir, mcp_http, username, password }
    agent:  { timeout_seconds, tls_verify, user_agent }
    servers:
      - { id, name, url, env, description }
"""

from __future__ import annotations

import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

# ${ENV_VAR} または ${ENV_VAR:-default} 形式の環境変数参照を検出する
_ENV_REF_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}")


@dataclass(frozen=True)
class ServerConfig:
    """管理対象ノード1台分の設定。"""

    id: str
    name: str
    url: str
    env: str = "development"
    description: str = ""

    def to_yaml_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "env": self.env,
            "description": self.description,
        }


@dataclass(frozen=True)
class AgentConfig:
    timeout_seconds: float = 5.0
    # TLS検証: True=システムCA / False=無検証 / strパス=指定CAファイルで検証
    # (httpx の verify 引数へそのまま渡す。CAファイル指定で自前CA署名の検証が可能)
    tls_verify: bool | str = True
    user_agent: str = "linux-mcp-server/0.1"
    # mTLS: クライアント証明書 (MCP Server 側)。client_key と対で指定する。
    client_cert: str = ""
    client_key: str = ""
    admin_token: str = ""


@dataclass(frozen=True)
class ConsoleConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    data_dir: str = "./data"
    mcp_http: bool = True
    mcp_http_path: str = "/mcp"
    username: str = ""
    password: str = ""
    auth_required: bool = True
    auth_mode: str = "basic"
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_browser_login: bool = False
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    oidc_authorization_endpoint: str = ""
    oidc_token_endpoint: str = ""
    session_cookie_secure: bool = True
    session_lifetime_minutes: int = 480
    max_sessions: int = 100
    idle_timeout_minutes: int = 60
    siem_webhook: str = ""
    siem_api_key: str = ""
    require_approval: bool = True
    approval_ttl_minutes: int = 15
    mcp_audit: bool = True
    max_parallel_nodes: int = 5
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 10
    # レート制限の高度化: 0 の場合は rate_limit_per_minute/burst へフォールバック
    rate_limit_write_per_minute: int = 0
    rate_limit_write_burst: int = 0
    rate_limit_token_per_minute: int = 0
    rate_limit_token_burst: int = 0
    audit_max_size_mb: int = 10
    audit_max_backups: int = 5
    audit_compress: bool = True


@dataclass(frozen=True)
class McpConfig:
    host: str = "127.0.0.1"
    port: int = 8090
    path: str = "/"
    enabled: bool = True
    stdio_token_env: str = "LINUX_MCP_TOKEN"


@dataclass(frozen=True)
class AppConfig:
    config_path: Path
    servers: tuple[ServerConfig, ...]
    agent: AgentConfig
    console: ConsoleConfig
    mcp: McpConfig = field(default_factory=McpConfig)
    # 元の config.yml の生データ (save 時に servers だけ差し替えて書き戻す)。
    # username/password/mcp_http_path/agent.client_cert など未知のキーを保持する。
    raw: dict[str, Any] = field(default_factory=dict)

    def server(self, server_id: str) -> ServerConfig | None:
        for server in self.servers:
            if server.id == server_id:
                return server
        return None

    @property
    def server_ids(self) -> list[str]:
        return [s.id for s in self.servers]

    @property
    def data_dir(self) -> Path:
        path = Path(self.console.data_dir)
        if not path.is_absolute():
            path = (self.config_path.parent / path).resolve()
        return path

    def add_server(self, server: ServerConfig) -> "AppConfig":
        """サーバーを追加してconfig.ymlに永続化し、新しいAppConfigを返す。"""
        new_servers = tuple(s for s in self.servers if s.id != server.id) + (server,)
        return AppConfig(
            config_path=self.config_path,
            servers=new_servers,
            agent=self.agent,
            console=self.console,
            mcp=self.mcp,
            raw=self.raw,
        )

    def remove_server(self, server_id: str) -> "AppConfig":
        """指定IDのサーバーを削除してconfig.ymlに永続化し、新しいAppConfigを返す。"""
        new_servers = tuple(s for s in self.servers if s.id != server_id)
        return AppConfig(
            config_path=self.config_path,
            servers=new_servers,
            agent=self.agent,
            console=self.console,
            mcp=self.mcp,
            raw=self.raw,
        )

    def save(self) -> None:
        """現在の設定をconfig.ymlに書き戻す。

        元の raw (console/agent の未知キー含む) をベースに、servers のみ
        差分を反映する。Basic認証の username/password、MCP HTTP path、
        mTLS 証明書などの設定を失わない。
        """
        data: dict[str, Any] = dict(self.raw)

        # 機密フィールドの ${ENV_VAR} 参照を save() 時に平文へ解決しないようにするための元データ。
        original_console = data.get("console") or {}
        original_agent = data.get("agent") or {}

        # console / agent の現行値をマージ (raw に存在しない項目だけ保証)。
        console_raw = dict(original_console)
        console_raw.update(
            {
                "host": self.console.host,
                "port": self.console.port,
                "data_dir": self.console.data_dir,
                "mcp_http": self.console.mcp_http,
                "require_approval": self.console.require_approval,
                "approval_ttl_minutes": self.console.approval_ttl_minutes,
                "mcp_audit": self.console.mcp_audit,
                "max_parallel_nodes": self.console.max_parallel_nodes,
                "rate_limit_per_minute": self.console.rate_limit_per_minute,
                "rate_limit_burst": self.console.rate_limit_burst,
                "rate_limit_write_per_minute": self.console.rate_limit_write_per_minute,
                "rate_limit_write_burst": self.console.rate_limit_write_burst,
                "rate_limit_token_per_minute": self.console.rate_limit_token_per_minute,
                "rate_limit_token_burst": self.console.rate_limit_token_burst,
                "audit_max_size_mb": self.console.audit_max_size_mb,
                "audit_max_backups": self.console.audit_max_backups,
                "audit_compress": self.console.audit_compress,
                "siem_webhook": self.console.siem_webhook,
                # siem_api_key は _preserve_env_ref で後から設定 (env ref 保持)
                # mcp_http_path は raw にあれば保持
                "mcp_http_path": self.console.mcp_http_path,
            }
        )
        # username/password は raw に無い場合は書き出さない (コメントで設定されるため)。
        if self.console.username:
            console_raw["username"] = self.console.username
        if self.console.password:
            console_raw["password"] = _preserve_env_ref(original_console, "password", self.console.password)
        console_raw["siem_api_key"] = _preserve_env_ref(original_console, "siem_api_key", self.console.siem_api_key)
        console_raw["auth_required"] = self.console.auth_required
        console_raw["auth_mode"] = self.console.auth_mode
        console_raw["oidc_issuer"] = self.console.oidc_issuer
        console_raw["oidc_audience"] = self.console.oidc_audience
        console_raw["oidc_jwks_url"] = self.console.oidc_jwks_url
        if self.console.oidc_browser_login:
            console_raw["oidc_browser_login"] = True
            console_raw["oidc_client_id"] = self.console.oidc_client_id
            console_raw["oidc_redirect_uri"] = self.console.oidc_redirect_uri
            if self.console.oidc_client_secret:
                console_raw["oidc_client_secret"] = _preserve_env_ref(original_console, "oidc_client_secret", self.console.oidc_client_secret)
            if self.console.oidc_authorization_endpoint:
                console_raw["oidc_authorization_endpoint"] = self.console.oidc_authorization_endpoint
            if self.console.oidc_token_endpoint:
                console_raw["oidc_token_endpoint"] = self.console.oidc_token_endpoint
            console_raw["session_lifetime_minutes"] = self.console.session_lifetime_minutes
            console_raw["session_cookie_secure"] = self.console.session_cookie_secure

        agent_raw = dict(original_agent)
        agent_raw.update(
            {
                "timeout_seconds": self.agent.timeout_seconds,
                "tls_verify": self.agent.tls_verify,
                "user_agent": self.agent.user_agent,
            }
        )
        # mTLS などの拡張キーは raw にあれば保持 (機密性あり: env ref を優先)
        if self.agent.client_cert:
            agent_raw["client_cert"] = _preserve_env_ref(original_agent, "client_cert", self.agent.client_cert)
        if self.agent.client_key:
            agent_raw["client_key"] = _preserve_env_ref(original_agent, "client_key", self.agent.client_key)
        if self.agent.admin_token:
            agent_raw["admin_token"] = _preserve_env_ref(original_agent, "admin_token", self.agent.admin_token)

        data["console"] = console_raw
        data["agent"] = agent_raw
        mcp_raw = dict(data.get("mcp") or {})
        mcp_raw.update(
            {
                "host": self.mcp.host,
                "port": self.mcp.port,
                "path": self.mcp.path,
                "enabled": self.mcp.enabled,
                "stdio_token_env": self.mcp.stdio_token_env,
            }
        )
        data["mcp"] = mcp_raw
        data["servers"] = [s.to_yaml_dict() for s in self.servers]

        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)


def _resolve_env_ref(match: re.Match[str]) -> str:
    """${ENV_VAR} または ${ENV_VAR:-default} を環境変数値へ置換する。

    変数未設定かつデフォルト無しは ValueError (fail-closed)。
    """
    name = match.group(1)
    static_part = match.group(0)[len("${" + name):]
    default = ""
    if static_part.startswith(":-"):
        default = static_part[2:-1]
    if name in os.environ:
        return os.environ[name]
    if ":-" in static_part:
        return default
    raise ValueError(
        f"config.yml で参照された環境変数 {name} が未設定です "
        f"(${{{name}}} または ${name}:-<default> を環境変数で提供してください)"
    )


def _expand_env(value: Any) -> Any:
    """config.yml の文字列値を再帰的に環境変数参照へ展開する。

    例:
      password: ${MCP_CONSOLE_PASSWORD}
      siem_api_key: ${MCP_SIEM_API_KEY:-}
    を環境変数の値へ置換する。未定義かつデフォルト無しはエラー。
    """
    if isinstance(value, str):
        if "${" not in value:
            return value
        return _ENV_REF_PATTERN.sub(_resolve_env_ref, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_expand_env(v) for v in value]
    return value


def _preserve_env_ref(source: dict[str, Any] | None, key: str, resolved: Any) -> Any:
    """save() 時に環境変数参照 (${...}) を平文へ解決した値で上書きしないためのヘルパー。"""
    if isinstance(source, dict):
        raw_value = source.get(key)
        if isinstance(raw_value, str) and "${" in raw_value:
            return raw_value
    return resolved


def _find_config(explicit: str | Path | None) -> Path:
    """config.yml のパスを解決する。引数 > 環境変数 > カレント > パッケージ同梱。"""
    if explicit is not None:
        path = Path(explicit)
        if not path.exists():
            raise FileNotFoundError(f"指定された設定ファイルが存在しません: {path}")
        return path

    env_path = os.environ.get("LINUX_MCP_CONFIG")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path

    candidates = [Path.cwd() / "config.yml", Path(__file__).resolve().parent.parent / "config.yml"]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "config.yml が見つかりません。LINUX_MCP_CONFIG 環境変数でパスを指定するか、"
        "mcp-server/config.yml を配置してください。"
    )


def _build_agent_ssl_context(tls_verify: bool | str, client_cert: str = "", client_key: str = "") -> ssl.SSLContext:
    """Agent通信用のSSLContextを構築する。

    httpx 0.28以降は ``verify=<CAパス>`` + ``cert=(crt, key)`` の組み合わせで
    クライアント証明書が送信されないケースがあるため、明示的にSSLContextを
    構築して ``verify=ctx`` として渡す。

    Args:
        tls_verify: True/False または CA証明書ファイルパス
        client_cert: クライアント証明書パス (空ならmTLS無効)
        client_key: クライアント秘密鍵パス

    Returns:
        構築済みSSLContext
    """
    if isinstance(tls_verify, ssl.SSLContext):
        ctx = tls_verify
    elif isinstance(tls_verify, str):
        # CA証明書パス指定
        ctx = ssl.create_default_context(cafile=tls_verify)
    elif tls_verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if client_cert and client_key:
        ctx.load_cert_chain(client_cert, client_key)
    return ctx


def _tls_verify_from_raw(raw: dict[str, Any]) -> bool | str:
    """agent.tls_verify を bool または CAファイルパス文字列として解釈する。

    - true/false (bool) → そのまま
    - "true"/"false" (文字列) → boolへ変換
    - その他の文字列 → CAファイルパス (httpx verifyへそのまま渡す)
    """
    value = raw.get("tls_verify", True)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "on", "1"}:
            return True
        if lowered in {"false", "no", "off", "0", ""}:
            return False
        return value
    return bool(value)


def _console_from_raw(raw: dict[str, Any], agent_user: str, agent_pass: str) -> ConsoleConfig:
    user = str(raw.get("username", "")) or agent_user
    password = str(raw.get("password", "")) or agent_pass
    return ConsoleConfig(
        host=str(raw.get("host", "127.0.0.1")),
        port=int(raw.get("port", 8080)),
        data_dir=str(raw.get("data_dir", "./data")),
        mcp_http=bool(raw.get("mcp_http", True)),
        mcp_http_path=str(raw.get("mcp_http_path", "/mcp")),
        username=user,
        password=password,
        auth_required=bool(raw.get("auth_required", True)),
        auth_mode=str(raw.get("auth_mode", "basic")),
        oidc_issuer=str(raw.get("oidc_issuer", "")),
        oidc_audience=str(raw.get("oidc_audience", "")),
        oidc_jwks_url=str(raw.get("oidc_jwks_url", "")),
        oidc_browser_login=bool(raw.get("oidc_browser_login", False)),
        oidc_client_id=str(raw.get("oidc_client_id", "")),
        oidc_client_secret=str(raw.get("oidc_client_secret", "")),
        oidc_redirect_uri=str(raw.get("oidc_redirect_uri", "")),
        oidc_authorization_endpoint=str(raw.get("oidc_authorization_endpoint", "")),
        oidc_token_endpoint=str(raw.get("oidc_token_endpoint", "")),
        session_lifetime_minutes=max(1, int(raw.get("session_lifetime_minutes", 480))),
        session_cookie_secure=bool(raw.get("session_cookie_secure", True)),
        siem_webhook=str(raw.get("siem_webhook", "")),
        siem_api_key=str(raw.get("siem_api_key", "")),
        require_approval=bool(raw.get("require_approval", True)),
        approval_ttl_minutes=int(raw.get("approval_ttl_minutes", 15)),
        mcp_audit=bool(raw.get("mcp_audit", True)),
        max_parallel_nodes=max(1, int(raw.get("max_parallel_nodes", 5))),
        rate_limit_per_minute=max(0, int(raw.get("rate_limit_per_minute", 60))),
        rate_limit_burst=max(0, int(raw.get("rate_limit_burst", 10))),
        rate_limit_write_per_minute=max(0, int(raw.get("rate_limit_write_per_minute", 0))),
        rate_limit_write_burst=max(0, int(raw.get("rate_limit_write_burst", 0))),
        rate_limit_token_per_minute=max(0, int(raw.get("rate_limit_token_per_minute", 0))),
        rate_limit_token_burst=max(0, int(raw.get("rate_limit_token_burst", 0))),
        audit_max_size_mb=max(0, int(raw.get("audit_max_size_mb", 10))),
        audit_max_backups=max(0, int(raw.get("audit_max_backups", 5))),
        audit_compress=bool(raw.get("audit_compress", True)),
    )


def load_config(path: str | Path | None = None) -> AppConfig:
    """config.yml を読み込んで AppConfig を返す。

    ``${ENV_VAR}`` 形式の機密参照は環境変数から解決する。解決後の値は
    ``AppConfig.raw`` (save() 用) には反映せず、平文が config.yml へ
    書き戻されないようにする。
    """
    config_path = _find_config(path).resolve()
    with open(config_path, "r", encoding="utf-8") as handle:
        raw: dict[str, Any] = yaml.safe_load(handle) or {}

    expanded = _expand_env(raw)

    servers_raw = expanded.get("servers") or []
    servers: list[ServerConfig] = []
    for item in servers_raw:
        servers.append(
            ServerConfig(
                id=str(item["id"]),
                name=str(item.get("name") or item["id"]),
                url=str(item["url"]).rstrip("/"),
                env=str(item.get("env", "development")),
                description=str(item.get("description", "")),
            )
        )
    ids = [s.id for s in servers]
    if len(ids) != len(set(ids)):
        raise ValueError(f"config.yml: サーバーIDが重複しています: {ids}")

    agent_raw = expanded.get("agent") or {}
    agent = AgentConfig(
        timeout_seconds=float(agent_raw.get("timeout_seconds", 5.0)),
        tls_verify=_tls_verify_from_raw(agent_raw),
        user_agent=str(agent_raw.get("user_agent", "linux-mcp-server/0.1")),
        client_cert=str(agent_raw.get("client_cert", "")),
        client_key=str(agent_raw.get("client_key", "")),
        admin_token=str(agent_raw.get("admin_token", "")) or os.environ.get("LINUX_MCP_AGENT_ADMIN_TOKEN", ""),
    )

    console = _console_from_raw(
        expanded.get("console") or {},
        agent_user=os.environ.get("LINUX_MCP_CONSOLE_USER", ""),
        agent_pass=os.environ.get("LINUX_MCP_CONSOLE_PASS", ""),
    )

    mcp_raw = expanded.get("mcp") or {}
    mcp = McpConfig(
        host=str(mcp_raw.get("host", "127.0.0.1")),
        port=int(mcp_raw.get("port", 8090)),
        path=str(mcp_raw.get("path", "/")),
        enabled=bool(mcp_raw.get("enabled", True)),
        stdio_token_env=str(mcp_raw.get("stdio_token_env", "LINUX_MCP_TOKEN")),
    )

    # OIDC設定のバリデーション
    if console.auth_mode == "oidc":
        if not console.oidc_issuer:
            raise ValueError("OIDCモードには oidc_issuer の設定が必要です")
        if not console.oidc_audience:
            raise ValueError("OIDCモードには oidc_audience の設定が必要です")
        if not console.oidc_jwks_url:
            raise ValueError("OIDCモードには oidc_jwks_url の設定が必要です")
        if not console.oidc_jwks_url.startswith("https://") and not _is_loopback_url(console.oidc_jwks_url):
            raise ValueError("oidc_jwks_url は https:// である必要があります (localhost 等のループバックは除く)")
        if console.oidc_browser_login:
            if not console.oidc_client_id:
                raise ValueError("oidc_browser_login には oidc_client_id の設定が必要です")
            if not console.oidc_redirect_uri:
                raise ValueError("oidc_browser_login には oidc_redirect_uri の設定が必要です")
            if not console.oidc_redirect_uri.startswith("https://") and not _is_loopback_url(console.oidc_redirect_uri):
                raise ValueError("oidc_redirect_uri は https:// である必要があります (localhost 等のループバックは除く)")
            if console.session_cookie_secure and not console.oidc_redirect_uri.startswith("https://"):
                raise ValueError(
                    "oidc_redirect_uri が http:// の場合は session_cookie_secure=false を明示してください"
                )

    return AppConfig(config_path=config_path, servers=tuple(servers), agent=agent, console=console, mcp=mcp, raw=raw)


def _is_loopback_url(url: str) -> bool:
    """URLのホストがループバック (localhost / 127.0.0.1 / ::1) かどうか。

    ローカル開発で http の IdP (Keycloak等) やコールバックURLを使えるようにする
    ための例外判定。外部ホストに対しては引き続き https:// を強制する。
    """
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")
    """環境変数から設定ファイルのパスを解決する。

    優先順位:
    1. MCP_CONFIG_FILE がセットされていればそのファイルを使用
    2. なければ RUN_MODE を読み、対応するファイルを使用
       - dev     -> config.dev.yml
       - testing -> config.testing.yml
       - prd     -> config.prd.yml
       - その他  -> config.dev.yml
    3. マップ先が存在しなければ config.dev.yml へフォールバック
    """
    custom = os.environ.get("MCP_CONFIG_FILE")
    if custom:
        p = Path(custom)
        if p.is_file():
            return p
        raise FileNotFoundError(f"MCP_CONFIG_FILE={custom} が存在しません")

    mode = os.environ.get("RUN_MODE", "dev")
    mapping = {
        "dev": "config.dev.yml",
        "testing": "config.testing.yml",
        "prd": "config.prd.yml",
    }
    candidate = mapping.get(mode, "config.dev.yml")
    if Path(candidate).is_file():
        return Path(candidate)

    # フォールバック: config.dev.yml
    fallback = Path("config.dev.yml")
    if fallback.is_file():
        return fallback

    raise FileNotFoundError(
        f"設定ファイルが見つかりません (RUN_MODE={mode}, candidate={candidate})"
    )


def load_config_auto() -> AppConfig:
    """環境変数に基づいて設定ファイルを自動解決して読み込む。"""
    return _load_config_from_path(resolve_config_path())
