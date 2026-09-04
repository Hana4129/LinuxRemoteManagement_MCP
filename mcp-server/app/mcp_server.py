"""FastMCP Tools — AI クライアント向け。各ノードの Agent API を呼び出す。

構築関数: ``build_mcp(config, store, approvals=None, audit=None) -> FastMCP``

Tools:
  list_servers()                       管理対象ノード一覧
  get_system_info(server)              OS / カーネル / 稼働時間
  get_disk_usage(server)               ディスク使用量
  get_processes(server)                プロセス一覧
  get_service_status(server, service)  サービス稼働状況
  get_service_logs(server, service, lines=100)
  read_file(server, path)              ファイル読取 (Agent allowlistで制限)
  request_restart_approval(server, service, reason="")   Human Approval 要求
  restart_service(server, service, approval_id="")       再起動 (承認済みapproval_idが必須)

Human Approval (設計書 §28 Level 3):
  restart_service は破壊的操作のため、人間の承認を必須とする。
  1) AI が request_restart_approval を呼ぶ → approval_id が発行される
  2) 人間が管理コンソールの「承認」タブで承認 (POST /api/approvals/{id}/approve)
  3) AI が restart_service(approval_id=...) を再実行 → 承認を1回限り消費して実行

監査 (設計書 §28 Level 2/3):
  すべてのTool呼び出しを McpAudit (JSONL, 0600) に記録する。
  actor はそのサーバーで使われたトークン名 (mcp:<name>)。生トークンは記録しない。
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable

from fastmcp import FastMCP

from .agent_client import AgentClient, AgentResult
from .approvals import ApprovalError, ApprovalStore
from .config import AppConfig, ServerConfig
from .db import TokenStore
from .mcp_audit import McpAudit

logger = logging.getLogger(__name__)


def build_mcp(
    config: AppConfig,
    store: TokenStore,
    approvals: ApprovalStore | None = None,
    audit: McpAudit | None = None,
) -> FastMCP:
    require_approval = bool(getattr(config.console, "require_approval", True))
    ttl_minutes = int(getattr(config.console, "approval_ttl_minutes", 15))
    if approvals is None and require_approval:
        # 承認ストアが渡されない場合 (stdio単独起動など) は data_dir 配下に作る
        try:
            approvals = ApprovalStore(config.data_dir / "approvals.db")
        except Exception as exc:  # noqa: BLE001 - 承認なし運用の妨げにしない
            logger.warning("ApprovalStore 初期化に失敗 (承認必須化を無効化できません): %s", exc)
            approvals = None

    mcp = FastMCP(
        name="linux-remote-management",
        instructions=(
            "リモートLinuxサーバー(Node)の状態を取得・操作するMCP server。"
            "server 引数には管理コンソール(config.yml) に登録されたサーバーIDを指定する。"
            "破壊的操作(restart_service)は operator スコープのトークンに加え、"
            "request_restart_approval で発行した approval_id と人間の承認が必要。"
        ),
    )

    def _server(server_id: str) -> ServerConfig:
        server = config.server(server_id)
        if server is None:
            raise ValueError(f"未知のサーバーID: {server_id!r} (登録済み: {config.server_ids})")
        return server

    def _actor(server_id: str | None) -> str:
        """監査ログの actor。そのサーバーで使われるトークン名を用いる。"""
        if not server_id:
            return "mcp"
        try:
            record = store.find_token_for_server(server_id)
        except Exception:  # noqa: BLE001
            record = None
        return f"mcp:{record.name}" if record is not None else "mcp:unknown"

    async def _run(
        action: str,
        server_id: str | None,
        params: dict[str, Any],
        coro_factory: Callable[[], Awaitable[dict]],
    ) -> dict:
        """Tool本体を実行し、成功/失敗を監査ログに記録する。"""
        started = time.perf_counter()
        try:
            result = await coro_factory()
            ok = bool(result.get("ok"))
            if audit is not None:
                audit.log(
                    actor=_actor(server_id),
                    action=action,
                    server=server_id,
                    params=params,
                    ok=ok,
                    error_kind=None if ok else str(result.get("error_kind")),
                    duration_ms=(time.perf_counter() - started) * 1000.0,
                )
            return result
        except Exception as exc:  # noqa: BLE001
            if audit is not None:
                audit.log(
                    actor=_actor(server_id),
                    action=action,
                    server=server_id,
                    params=params,
                    ok=False,
                    error_kind=type(exc).__name__,
                    detail=str(exc),
                    duration_ms=(time.perf_counter() - started) * 1000.0,
                )
            raise

    def _payload(result: AgentResult) -> dict:
        if result.ok:
            return {"ok": True, "data": result.data}
        return {"ok": False, "error_kind": result.error_kind, "error": result.error}

    @mcp.tool
    def list_servers() -> dict:
        """管理対象ノードの一覧を返す。"""
        servers = [{"id": s.id, "name": s.name, "url": s.url, "env": s.env} for s in config.servers]
        if audit is not None:
            audit.log(actor="mcp", action="list_servers", params={}, ok=True)
        return {"servers": servers}

    @mcp.tool
    async def get_system_info(server: str) -> dict:
        """指定サーバーのOS・カーネル・稼働時間などのシステム情報を取得する。"""

        async def _call() -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.system_info(_server(server)))

        return await _run("get_system_info", server, {}, _call)

    @mcp.tool
    async def get_disk_usage(server: str) -> dict:
        """指定サーバーのディスク使用量を取得する。"""

        async def _call() -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.disk_usage(_server(server)))

        return await _run("get_disk_usage", server, {}, _call)

    @mcp.tool
    async def get_processes(server: str) -> dict:
        """指定サーバーのプロセス一覧を取得する。"""

        async def _call() -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.processes(_server(server)))

        return await _run("get_processes", server, {}, _call)

    @mcp.tool
    async def get_service_status(server: str, service: str) -> dict:
        """指定サーバー上のサービスの稼働状況を取得する。"""

        async def _call() -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.service_status(_server(server), service))

        return await _run("get_service_status", server, {"service": service}, _call)

    @mcp.tool
    async def get_service_logs(server: str, service: str, lines: int = 100) -> dict:
        """指定サービスの最近のログを取得する。lines=取得する最大行数。"""

        async def _call() -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.service_logs(_server(server), service, lines=lines))

        return await _run("get_service_logs", server, {"service": service, "lines": lines}, _call)

    @mcp.tool
    async def read_file(server: str, path: str) -> dict:
        """指定サーバーのファイルを読み取る (Agent側allowlistで制限される)。"""

        async def _call() -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.read_file(_server(server), path))

        return await _run("read_file", server, {"path": path}, _call)

    @mcp.tool
    async def request_restart_approval(server: str, service: str, reason: str = "") -> dict:
        """restart_service の事前承認要求を作成する。

        返された approval_id を人間 (運用者) に伝え、管理コンソールの
        「承認」タブで承認してもらう。承認後、restart_service(approval_id=...) で実行。
        承認の有効期限は ttl_minutes (デフォルト15分)。
        """

        async def _call() -> dict:
            if approvals is None:
                return {
                    "ok": False,
                    "error_kind": "approval_unavailable",
                    "error": "承認ストアが初期化されていません (config.yml の require_approval を確認してください)。",
                }
            target = _server(server)
            rec = approvals.request(
                server_id=target.id,
                service=service,
                reason=reason,
                requested_by="mcp",
                ttl_minutes=ttl_minutes,
            )
            return {
                "ok": True,
                "data": {
                    **rec.to_dict(),
                    "ttl_minutes": ttl_minutes,
                    "how_to_approve": "管理コンソール「承認」タブでこの要求を承認してください",
                },
            }

        return await _run("request_restart_approval", server, {"service": service, "reason": reason}, _call)

    @mcp.tool
    async def restart_service(server: str, service: str, approval_id: str = "") -> dict:
        """指定サーバー上のサービスを再起動する (破壊的操作)。

        人間の承認が必須: まず request_restart_approval で approval_id を発行し、
        人間が管理コンソールで承認した後、このツールに approval_id を渡して実行する。
        承認は1回限り消費され、期限切れの承認は拒否される。
        実行には operator スコープのトークンが必要。
        """

        async def _call() -> dict:
            target = _server(server)
            if require_approval:
                if approvals is None:
                    return {
                        "ok": False,
                        "error_kind": "approval_unavailable",
                        "error": "承認ストアが初期化されていないため再起動を実行できません。",
                    }
                if not approval_id:
                    rec = approvals.request(
                        server_id=target.id,
                        service=service,
                        requested_by="mcp",
                        ttl_minutes=ttl_minutes,
                    )
                    return {
                        "ok": False,
                        "error_kind": "approval_required",
                        "error": "破壊的操作 (restart_service) には人間の承認が必要です。",
                        "approval": rec.to_dict(),
                        "next_steps": (
                            "1) 運用者に approval_id=" + rec.id + " の承認を依頼する"
                            " 2) 管理コンソール「承認」タブで承認"
                            " 3) restart_service(approval_id=...) を再実行"
                        ),
                    }
                rec = approvals.get(approval_id)
                if rec is None:
                    return {"ok": False, "error_kind": "approval_invalid", "error": f"承認が見つかりません: {approval_id}"}
                if rec.server_id != target.id or rec.service != service:
                    return {
                        "ok": False,
                        "error_kind": "approval_mismatch",
                        "error": "承認の対象 (server/service) が実行内容と一致しません。",
                    }
                # 承認を消費する前にトークン (operatorスコープ) の存在を確認する。
                # トークン欠如で承認を無駄にしないための順序保障。
                if store.find_token_for_server(target.id, scope="operator") is None:
                    return {
                        "ok": False,
                        "error_kind": "no_token",
                        "error": f"このサーバーには scope=operator のトークンがありません (server={target.id})。",
                    }
                try:
                    approvals.consume(approval_id)  # approved → executed (1回限り・期限チェック込み)
                except ApprovalError as exc:
                    return {"ok": False, "error_kind": "approval_invalid", "error": str(exc)}
            async with AgentClient(config, store) as agent:
                return _payload(await agent.restart_service(target, service))

        return await _run(
            "restart_service", server, {"service": service, "approval_id": bool(approval_id)}, _call
        )

    # ---- 複数ノード一括操作 ----

    max_parallel = int(getattr(config.console, "max_parallel_nodes", 5) or 5)
    _semaphore = asyncio.Semaphore(max(1, max_parallel))

    def _resolve_server_ids(servers: list[str] | None) -> list[str]:
        """servers が空/None/'all' なら全ノード、それ以外は指定IDのリスト。"""
        if not servers or servers == ["all"]:
            return list(config.server_ids)
        return list(servers)

    async def _gather_results(
        action: str,
        server_ids: list[str],
        coro_factory: Callable[[ServerConfig], Awaitable[dict]],
    ) -> dict:
        """複数ノードへ同一操作を並列実行し、結果をノードごとに集約する。"""

        async def _run_one(sid: str) -> tuple[str, dict]:
            async with _semaphore:
                try:
                    target = _server(sid)
                except ValueError as exc:
                    return sid, {"ok": False, "error_kind": "unknown_server", "error": str(exc)}
                try:
                    return sid, await coro_factory(target)
                except Exception as exc:  # noqa: BLE001 - 1ノードの失敗で全体を止めない
                    return sid, {"ok": False, "error_kind": type(exc).__name__, "error": str(exc)}

        results = await asyncio.gather(*(_run_one(sid) for sid in server_ids))
        by_server: dict[str, dict] = {}
        for sid, res in results:
            by_server[sid] = res
        ok_count = sum(1 for r in by_server.values() if r.get("ok"))
        summary = {
            "total": len(by_server),
            "ok": ok_count,
            "failed": len(by_server) - ok_count,
        }
        if audit is not None:
            audit.log(
                actor=_actor(server_ids[0] if server_ids else None),
                action=action,
                server=None,
                params={"servers": server_ids},
                ok=(summary["failed"] == 0),
                detail=f"ok={summary['ok']}/{summary['total']}",
            )
        return {"ok": summary["failed"] == 0, "summary": summary, "results": by_server}

    @mcp.tool
    async def get_status_all(servers: list[str] | None = None) -> dict:
        """複数ノードのシステム情報を一括取得する。

        servers にノードIDのリストを指定する (省略または ["all"] で全ノード)。
        並列実行数は max_parallel_nodes (デフォルト 5) に制限される。
        結果はノードIDごとに集約して返す。
        """
        ids = _resolve_server_ids(servers)

        async def _call(target: ServerConfig) -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.system_info(target))

        return await _gather_results("get_status_all", ids, _call)

    @mcp.tool
    async def get_service_status_all(servers: list[str] | None = None, service: str = "") -> dict:
        """複数ノードの指定サービスの稼働状況を一括取得する。

        servers にノードIDのリストを指定する (省略または ["all"] で全ノード)。
        service は必須。
        """
        if not service:
            return {"ok": False, "error_kind": "missing_service", "error": "service を指定してください。"}
        ids = _resolve_server_ids(servers)

        async def _call(target: ServerConfig) -> dict:
            async with AgentClient(config, store) as agent:
                return _payload(await agent.service_status(target, service))

        return await _gather_results("get_service_status_all", ids, _call)

    @mcp.tool
    async def restart_service_all(
        servers: list[str] | None = None, service: str = "", approval_id: str = ""
    ) -> dict:
        """複数ノードの指定サービスを一括再起動する (破壊的操作)。

        人間の承認が必須: まず request_restart_approval で各ノードの approval_id を
        発行し、人間が管理コンソールで承認した後、ノードごとの approval_id を
        カンマ区切りで渡して実行する (例: "apr_aaa,apr_bbb")。
        承認は実行時に1回限り消費される。
        実行には全指定ノードで operator スコープのトークンが必要。
        """
        if not service:
            return {"ok": False, "error_kind": "missing_service", "error": "service を指定してください。"}
        ids = _resolve_server_ids(servers)
        approval_map: dict[str, str] = {}
        if approval_id:
            for pair in approval_id.split(","):
                pair = pair.strip()
                if "=" in pair:
                    sid, aid = pair.split("=", 1)
                    approval_map[sid.strip()] = aid.strip()
                elif len(ids) == 1:
                    approval_map[ids[0]] = pair

        async def _call(target: ServerConfig) -> dict:
            aid = approval_map.get(target.id, "")
            if require_approval:
                if approvals is None:
                    return {
                        "ok": False,
                        "error_kind": "approval_unavailable",
                        "error": "承認ストアが初期化されていないため再起動を実行できません。",
                    }
                if not aid:
                    rec = approvals.request(
                        server_id=target.id,
                        service=service,
                        requested_by="mcp",
                        ttl_minutes=ttl_minutes,
                    )
                    return {
                        "ok": False,
                        "error_kind": "approval_required",
                        "error": f"破壊的操作には人間の承認が必要です (server={target.id})。",
                        "approval": rec.to_dict(),
                    }
                rec = approvals.get(aid)
                if rec is None:
                    return {"ok": False, "error_kind": "approval_invalid", "error": f"承認が見つかりません: {aid}"}
                if rec.server_id != target.id or rec.service != service:
                    return {
                        "ok": False,
                        "error_kind": "approval_mismatch",
                        "error": f"承認の対象が一致しません (server={target.id})。",
                    }
                if store.find_token_for_server(target.id, scope="operator") is None:
                    return {
                        "ok": False,
                        "error_kind": "no_token",
                        "error": f"scope=operator のトークンがありません (server={target.id})。",
                    }
                try:
                    approvals.consume(aid)
                except ApprovalError as exc:
                    return {"ok": False, "error_kind": "approval_invalid", "error": str(exc)}
            async with AgentClient(config, store) as agent:
                return _payload(await agent.restart_service(target, service))

        return await _gather_results("restart_service_all", ids, _call)

    @mcp.tool
    async def execute_command(server: str, command: str) -> dict:
        """指定サーバーでコマンドを実行する (allowlistで制限)。

        operator スコープのトークンが必要。
        実行はAgent側のcommand allowlistで制限される。
        タイムアウトはAgent側で設定された秒数。
        """

        async def _call() -> dict:
            target = _server(server)
            async with AgentClient(config, store) as agent:
                return _payload(await agent.execute_command(target, command))

        return await _run("execute_command", server, {"command": command}, _call)

    @mcp.tool
    async def write_file(server: str, path: str, content: str) -> dict:
        """指定サーバーにファイルを書き込む (write_paths allowlistで制限)。

        operator スコープのトークンが必要。
        実行はAgent側のwrite_paths allowlistで制限される。
        既存ファイルは自動的にバックアップされる (.bak)。
        """

        async def _call() -> dict:
            target = _server(server)
            async with AgentClient(config, store) as agent:
                return _payload(await agent.write_file(target, path, content))

        return await _run("write_file", server, {"path": path}, _call)

    return mcp
