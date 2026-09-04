"""Linux Agent (HTTPS) API クライアント。

MCP Server はこのクライアントを通じて、各ノードの Agent に
Bearer Token 認証付きで HTTPS リクエストを送信する。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import ServerConfig
from .db import TokenStore

__all__ = ["AgentClient", "AgentResult", "AgentError"]

_REFUSED_MARKERS = ("refused", "10061", "actively refused", "拒否")


class AgentError(Exception):
    """Agent API呼び出しの失敗を表す例外。"""

    def __init__(self, message: str, kind: str = "error", status_code: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code


@dataclass
class AgentResult:
    ok: bool
    data: Any = None
    error: str | None = None
    error_kind: str | None = None
    status_code: int | None = None
    latency_ms: float = 0.0

    @classmethod
    def success(cls, data: Any, status_code: int | None, latency_ms: float) -> "AgentResult":
        return cls(ok=True, data=data, status_code=status_code, latency_ms=latency_ms)

    @classmethod
    def failure(cls, message: str, kind: str = "error", latency_ms: float = 0.0) -> "AgentResult":
        return cls(ok=False, error=message, error_kind=kind, latency_ms=latency_ms)


def _brief(message: str, limit: int = 160) -> str:
    if not message:
        return ""
    return message if len(message) <= limit else message[:limit] + "…"


def _looks_like_refused(exc: Exception) -> bool:
    text = str(exc)
    return any(marker in text for marker in _REFUSED_MARKERS)


def _elapsed(started: float) -> float:
    return round((time.perf_counter() - started) * 1000.0, 1)


class AgentClient:
    """各ノードの Agent API への非同期HTTPクライアント。"""

    def __init__(self, config: Any, store: TokenStore):
        self._config = config
        self._store = store
        # mTLS: client_cert/client_key が設定されていればクライアント証明書を提示する
        client_cert = getattr(config.agent, "client_cert", "") or ""
        client_key = getattr(config.agent, "client_key", "") or ""
        cert = None
        if client_cert and client_key:
            cert = (client_cert, client_key)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.agent.timeout_seconds),
            verify=config.agent.tls_verify,
            cert=cert,
            headers={"User-Agent": config.agent.user_agent, "Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AgentClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _token_for(self, server_id: str, scope: str | None = None):
        return self._store.find_token_for_server(server_id, scope=scope)

    async def request(
        self,
        server: ServerConfig,
        method: str,
        path: str,
        *,
        scope: str | None = None,
        json_body: dict | None = None,
        params: dict | None = None,
    ) -> AgentResult:
        record = None
        token = None
        if scope is None:
            record = self._token_for(server.id)
            if record is None:
                return AgentResult.failure(
                    "このサーバー用のトークンが未発行です。管理コンソールで発行してください。", kind="no_token"
                )
            token = record.token_raw
        else:
            record = self._token_for(server.id, scope=scope)
            if record is None:
                return AgentResult.failure(
                    f"このサーバーには scope={scope} のトークンがありません。", kind="no_token"
                )
            token = record.token_raw
        if not token:
            return AgentResult.failure("トークン値が空です。", kind="auth")

        url = server.url.rstrip("/") + path
        started = time.perf_counter()
        try:
            resp = await self._client.request(
                method,
                url,
                headers={"Authorization": f"Bearer {token}"},
                json=json_body,
                params=params,
            )
        except httpx.ConnectError as exc:
            kind = "not_responding" if _looks_like_refused(exc) else "unreachable"
            return AgentResult.failure(f"接続失敗 ({kind}): {_brief(str(exc))}", kind=kind, latency_ms=_elapsed(started))
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
            return AgentResult.failure(f"タイムアウト: {_brief(str(exc))}", kind="unreachable", latency_ms=_elapsed(started))
        except httpx.HTTPError as exc:
            return AgentResult.failure(f"通信エラー: {_brief(str(exc))}", kind="unreachable", latency_ms=_elapsed(started))
        except Exception as exc:  # noqa: BLE001
            return AgentResult.failure(f"エラー: {_brief(str(exc))}", kind="error", latency_ms=_elapsed(started))

        latency = _elapsed(started)

        if resp.status_code in (401, 403):
            return AgentResult.failure(
                f"認証エラー (HTTP {resp.status_code})：トークンが無効か権限がありません。",
                kind="auth",
                latency_ms=latency,
            )
        if resp.status_code >= 400:
            return AgentResult.failure(
                f"HTTPエラー {resp.status_code}: {_brief(resp.text)}", kind="http_error", latency_ms=latency
            )

        try:
            data = resp.json()
        except ValueError:
            data = {"raw": resp.text[:2000]}

        if record is not None:
            try:
                self._store.touch_last_used(record.id)
            except Exception:
                pass
        return AgentResult.success(data=data, status_code=resp.status_code, latency_ms=latency)

    # ---- endpoint wrappers ----
    async def health(self, server: ServerConfig) -> AgentResult:
        return await self.request(server, "GET", "/v1/health")

    async def system_info(self, server: ServerConfig) -> AgentResult:
        return await self.request(server, "GET", "/v1/system")

    async def disk_usage(self, server: ServerConfig) -> AgentResult:
        return await self.request(server, "GET", "/v1/disk")

    async def processes(self, server: ServerConfig) -> AgentResult:
        return await self.request(server, "GET", "/v1/processes")

    async def service_status(self, server: ServerConfig, service: str) -> AgentResult:
        return await self.request(server, "GET", f"/v1/services/{service}")

    async def restart_service(self, server: ServerConfig, service: str) -> AgentResult:
        return await self.request(server, "POST", f"/v1/services/{service}/restart", scope="operator")

    async def service_logs(self, server: ServerConfig, service: str, lines: int = 100) -> AgentResult:
        return await self.request(server, "GET", f"/v1/services/{service}/logs", params={"lines": lines})

    async def read_file(self, server: ServerConfig, path: str) -> AgentResult:
        return await self.request(server, "GET", "/v1/files", params={"path": path})

    async def execute_command(self, server: ServerConfig, command: str) -> AgentResult:
        return await self.request(server, "POST", "/v1/execute", scope="operator", json_body={"command": command})

    async def write_file(self, server: ServerConfig, path: str, content: str) -> AgentResult:
        # Agent API 契約 (openapi-agent.yml): path は query パラメータ、content は JSON ボディ
        return await self.request(
            server, "POST", "/v1/files", scope="operator", params={"path": path}, json_body={"content": content}
        )

