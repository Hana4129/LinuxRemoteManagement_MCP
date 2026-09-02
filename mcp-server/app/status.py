"""ノード状況の集約。

Agent の /v1/health と /v1/system の結果をもとに、
「インストール状況」「OSバージョン」「稼働時間」を判定する。
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from typing import Any

from .agent_client import AgentClient
from .config import ServerConfig
from .tokens import humanize_uptime, now_iso

# インストール状況の分類 → ラベル（UI表示用）
INSTALL_STATUS_LABELS: dict[str, str] = {
    "running": "導入済み・稼働中",
    "auth_error": "導入済み（認証エラー）",
    "http_error": "導入済み（異常応答）",
    "not_responding": "未導入 / Agent未起動",
    "unreachable": "到達不能",
    "no_token": "トークン未発行",
    "error": "エラー",
}


def install_status_label(kind: str | None) -> str:
    return INSTALL_STATUS_LABELS.get(kind or "error", INSTALL_STATUS_LABELS["error"])


def _empty_node(server: ServerConfig) -> dict[str, Any]:
    return {
        "id": server.id,
        "name": server.name,
        "url": server.url,
        "env": server.env,
        "description": server.description,
        "install_status": "error",
        "install_status_label": install_status_label("error"),
        "reachable": False,
        "health": None,
        "os": None,
        "agent_version": None,
        "latency_ms": None,
        "error": None,
        "checked_at": now_iso(),
    }


async def collect_node_status(agent: AgentClient, server: ServerConfig) -> dict[str, Any]:
    """1台のノード状況を収集する。"""
    node = _empty_node(server)
    checked_at = now_iso()

    health = await agent.health(server)
    node["latency_ms"] = round(health.latency_ms, 1)
    node["checked_at"] = checked_at

    if not health.ok:
        node["install_status"] = health.error_kind or "error"
        node["install_status_label"] = install_status_label(node["install_status"])
        node["error"] = health.error
        return node

    # Health OK: Agentは生きている → インストール済み
    node["reachable"] = True
    node["health"] = health.data
    node["agent_version"] = (health.data or {}).get("agent_version")
    node["install_status"] = "running"
    node["install_status_label"] = install_status_label("running")
    node["latency_ms"] = round(health.latency_ms, 1)

    system = await agent.system_info(server)
    if system.ok and isinstance(system.data, dict):
        data = system.data
        node["os"] = {
            "hostname": data.get("hostname"),
            "os": data.get("os") or data.get("os_pretty"),
            "kernel": data.get("kernel"),
            "arch": data.get("arch"),
            "uptime_seconds": data.get("uptime_seconds"),
            "uptime_human": humanize_uptime(data.get("uptime_seconds")),
            "agent_version": data.get("agent_version"),
        }
    else:
        # Healthは通るがsystem取得失敗 → 導入済みだが情報取得異常
        node["install_status"] = system.error_kind or "http_error"
        node["install_status_label"] = install_status_label(node["install_status"])
        node["error"] = system.error or health.error
    return node


async def collect_all_nodes(agent: AgentClient, servers: list[ServerConfig]) -> list[dict[str, Any]]:
    """全ノードの状況を並行収集する。"""
    results = await asyncio.gather(
        *(collect_node_status(agent, server) for server in servers),
        return_exceptions=False,
    )
    return list(results)


def summarize_nodes(nodes: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in nodes:
        key = node["install_status"]
        counts[key] = counts.get(key, 0) + 1
    counts["total"] = len(nodes)
    counts["problems"] = sum(1 for n in nodes if n["install_status"] not in ("running",))
    counts["running"] = counts.get("running", 0)
    return counts
