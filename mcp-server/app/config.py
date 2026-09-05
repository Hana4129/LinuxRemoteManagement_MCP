"""設定の読み込みと設定オブジェクト定義。

`config.yml` は以下の構造を期待する。

    console: { host, port, data_dir, mcp_http, username, password }
    agent:  { timeout_seconds, tls_verify, user_agent }
    servers:
      - { id, name, url, env, description }
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


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
    tls_verify: bool = True
    user_agent: str = "linux-mcp-server/0.1"
    # mTLS: クライアント証明書 (MCP Server 側)。client_key と対で指定する。
    client_cert: str = ""
    client_key: str = ""


@dataclass(frozen=True)
class ConsoleConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    data_dir: str = "./data"
    mcp_http: bool = True
    mcp_http_path: str = "/mcp"
    username: str = ""
    password: str = ""
    require_approval: bool = True
    approval_ttl_minutes: int = 15
    mcp_audit: bool = True
    max_parallel_nodes: int = 5
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 10
    audit_max_size_mb: int = 10
    audit_max_backups: int = 5
    audit_compress: bool = True


@dataclass(frozen=True)
class AppConfig:
    config_path: Path
    servers: tuple[ServerConfig, ...]
    agent: AgentConfig
    console: ConsoleConfig
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
            raw=self.raw,
        )

    def save(self) -> None:
        """現在の設定をconfig.ymlに書き戻す。

        元の raw (console/agent の未知キー含む) をベースに、servers のみ
        差分を反映する。Basic認証の username/password、MCP HTTP path、
        mTLS 証明書などの設定を失わない。
        """
        data: dict[str, Any] = dict(self.raw)

        # console / agent の現行値をマージ (raw に存在しない項目だけ保証)。
        console_raw = dict(data.get("console") or {})
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
                "audit_max_size_mb": self.console.audit_max_size_mb,
                "audit_max_backups": self.console.audit_max_backups,
                "audit_compress": self.console.audit_compress,
                # mcp_http_path は raw にあれば保持
                "mcp_http_path": self.console.mcp_http_path,
            }
        )
        # username/password は raw に無い場合は書き出さない (コメントで設定されるため)。
        if self.console.username:
            console_raw["username"] = self.console.username
        if self.console.password:
            console_raw["password"] = self.console.password

        agent_raw = dict(data.get("agent") or {})
        agent_raw.update(
            {
                "timeout_seconds": self.agent.timeout_seconds,
                "tls_verify": self.agent.tls_verify,
                "user_agent": self.agent.user_agent,
            }
        )
        # mTLS などの拡張キーは raw にあれば保持
        if self.agent.client_cert:
            agent_raw["client_cert"] = self.agent.client_cert
        if self.agent.client_key:
            agent_raw["client_key"] = self.agent.client_key

        data["console"] = console_raw
        data["agent"] = agent_raw
        data["servers"] = [s.to_yaml_dict() for s in self.servers]

        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)


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
        require_approval=bool(raw.get("require_approval", True)),
        approval_ttl_minutes=int(raw.get("approval_ttl_minutes", 15)),
        mcp_audit=bool(raw.get("mcp_audit", True)),
        max_parallel_nodes=max(1, int(raw.get("max_parallel_nodes", 5))),
        rate_limit_per_minute=max(0, int(raw.get("rate_limit_per_minute", 60))),
        rate_limit_burst=max(0, int(raw.get("rate_limit_burst", 10))),
        audit_max_size_mb=max(0, int(raw.get("audit_max_size_mb", 10))),
        audit_max_backups=max(0, int(raw.get("audit_max_backups", 5))),
        audit_compress=bool(raw.get("audit_compress", True)),
    )


def load_config(path: str | Path | None = None) -> AppConfig:
    """config.yml を読み込んで AppConfig を返す。"""
    config_path = _find_config(path).resolve()
    with open(config_path, "r", encoding="utf-8") as handle:
        raw: dict[str, Any] = yaml.safe_load(handle) or {}

    servers_raw = raw.get("servers") or []
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

    agent_raw = raw.get("agent") or {}
    agent = AgentConfig(
        timeout_seconds=float(agent_raw.get("timeout_seconds", 5.0)),
        tls_verify=bool(agent_raw.get("tls_verify", True)),
        user_agent=str(agent_raw.get("user_agent", "linux-mcp-server/0.1")),
        client_cert=str(agent_raw.get("client_cert", "")),
        client_key=str(agent_raw.get("client_key", "")),
    )

    console = _console_from_raw(
        raw.get("console") or {},
        agent_user=os.environ.get("LINUX_MCP_CONSOLE_USER", ""),
        agent_pass=os.environ.get("LINUX_MCP_CONSOLE_PASS", ""),
    )

    return AppConfig(config_path=config_path, servers=tuple(servers), agent=agent, console=console, raw=raw)
