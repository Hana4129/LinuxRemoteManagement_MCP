""""""""""""管理コンソール HTTP API。

- GET  /api/meta            アプリ/サーバー/スコープのメタ
- GET  /api/nodes            ノード一覧 (インストール状況/OS/稼働時間を判定済み)
- GET  /api/nodes/{id}       ノード詳細 (system + disk + プロセス数)
- GET  /api/nodes/{id}/disk
- GET  /api/nodes/{id}/processes
- GET  /api/tokens           トークン一覧 (生値は返さない)
- POST /api/tokens           トークン発行 (生トークンを一度だけ返す)
- POST /api/tokens/import    外部で発行したトークンを登録
- POST /api/tokens/{id}/rotate  トークンローテーション
- GET  /api/tokens/{id}/rotations  ローテーション履歴
- POST /api/tokens/{id}/revoke  失効
- DEL  /api/tokens/{id}       削除
- POST /api/tokens/cleanup-grace-periods  グラ期間経過トークン一括無効化
""""""""""""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from . import __version__
from .agent_client import AgentClient, AgentResult
from .config import ServerConfig
from .db import TokenStore
from .status import collect_all_nodes, collect_node_status, summarize_nodes
from .tokens import SCOPES, now_iso

log = logging.getLogger(__name__)

meta_router = APIRouter(prefix="/api", tags=["meta"])
nodes_router = APIRouter(prefix="/api/nodes", tags=["nodes"])
tokens_router = APIRouter(prefix="/api/tokens", tags=["tokens"])


class TokenCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="トークンの説明・用途")
    scope: Literal["readonly", "operator"]
    server_ids: list[str] = Field(..., min_length=1, description='アクセス許可するサーバーID ("*" で全許可)')
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="有効期限(日)。未指定=無期限")


class TokenRotateRequest(BaseModel):
    grace_period_days: int = Field(default=7, ge=1, le=90, description="新旧トークンのグラ期間(日)")
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="新しいトークンの有効期限(日)")


class TokenImportRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    token: str = Field(..., min_length=1, description="登録する生トークン")
    server_ids: list[str] = Field(..., min_length=1)
    scope: Literal["readonly", "operator"]
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


def _payload(result: AgentResult) -> dict:
    if result.ok:
        return {"ok": True, "data": result.data}
    return {"ok": False, "error_kind": result.error_kind, "error": result.error}


def _server_or_404(request: Request, server_id: str) -> ServerConfig:
    server = request.app.state.config.server(server_id)
    if server is None:
        raise HTTPException(
            status_code=404, detail=f"未知のサーバーID: {server_id} (登録済み: {request.app.state.config.server_ids})"
        )
    return server


def _validate_server_ids(request: Request, ids: list[str]) -> list[str]:
    cfg = request.app.state.config
    available = set(cfg.server_ids)
    bad = [i for i in ids if i != "*" and i not in available]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"未登録のサーバーID: {bad} (有効: {sorted(available)} または '*')",
        )
    return sorted(set(ids))


# ---- meta ----
@meta_router.get("/meta")
def get_meta(request: Request) -> dict[str, Any]:
    cfg = request.app.state.config
    return {
        "app": "Linux Remote Management MCP Server",
        "version": __version__,
        "servers": [{"id": s.id, "name": s.name, "env": s.env, "url": s.url} for s in cfg.servers],
        "scopes": list(SCOPES),
        "mcp": {
            "http_enabled": bool(getattr(request.app.state, "mcp_http_enabled", False)),
            "http_path": cfg.console.mcp_http_path if getattr(request.app.state, "mcp_http_enabled", False) else None,
            "stdio_entry": "python -m app.mcp_entry",
            "http_entry": "python -m app.mcp_http_entry",
        },
        "token_store": str(cfg.data_dir / "tokens.db"),
    }


# ---- nodes ----
@nodes_router.get("")
async def list_nodes(request: Request) -> dict[str, Any]:
    cfg = request.app.state.config
    async with AgentClient(cfg, request.app.state.store) as agent:
        nodes = await collect_all_nodes(agent, cfg.servers)
    return {"checked_at": now_iso(), "summary": summarize_nodes(nodes), "nodes": nodes}


@nodes_router.get("/{server_id}")
async def node_detail(request: Request, server_id: str) -> dict[str, Any]:
    server = _server_or_404(request, server_id)
    cfg = request.app.state.config
    async with AgentClient(cfg, request.app.state.store) as agent:
        status_node = await collect_node_status(agent, server)
        detail: dict[str, Any] = {"node": status_node, "disk": None, "processes_count": None}
        if status_node.get("reachable"):
            disk = await agent.disk_usage(server)
            if disk.ok:
                detail["disk"] = disk.data
            procs = await agent.processes(server)
            if procs.ok and isinstance(procs.data, dict):
                detail["processes_count"] = len(procs.data.get("processes", []))
    return detail


@nodes_router.get("/{server_id}/processes")
async def node_processes(request: Request, server_id: str, limit: int = 100) -> dict[str, Any]:
    server = _server_or_404(request, server_id)
    async with AgentClient(request.app.state.config, request.app.state.store) as agent:
        result = await agent.processes(server)
    return _payload(result)


@nodes_router.get("/{server_id}/disk")
async def node_disk(request: Request, server_id: str) -> dict[str, Any]:
    server = _server_or_404(request, server_id)
    async with AgentClient(request.app.state.config, request.app.state.store) as agent:
        result = await agent.disk_usage(server)
    return _payload(result)


# ---- tokens ----
@tokens_router.get("")
def list_tokens(request: Request) -> dict[str, Any]:
    """トークン一覧を返す (生トークンは含まれない)。"""
    store: TokenStore = request.app.state.store
    records = store.list_tokens()
    return {"tokens": [t.to_dict() for t in records]}


@tokens_router.post("")
def create_token(request: Request, payload: TokenCreateRequest) -> dict[str, Any]:
    """新しいMCPトークンを発行する。生トークンはこのレスポンスで一度だけ返される。"""
    store: TokenStore = request.app.state.store
    server_ids = _validate_server_ids(request, payload.server_ids)
    client_host = request.client.host if request.client is not None else ""
    record, raw = store.create_token(
        name=payload.name,
        server_ids=server_ids,
        scope=payload.scope,
        expires_in_days=payload.expires_in_days,
        created_by=f"console:{client_host}",
    )
    log.info("トークン発行 id=%s name=%r scope=%s servers=%s", record.id, payload.name, payload.scope, server_ids)
    return {"token": raw, "record": record.to_dict()}


@tokens_router.post("/import")
def import_token(request: Request, payload: TokenImportRequest) -> dict[str, Any]:
    """外部で発行済みのトークンをストアへ登録する (Agent側で生成したトークン等)。"""
    store: TokenStore = request.app.state.store
    server_ids = _validate_server_ids(request, payload.server_ids)
    record = store.import_token(
        name=payload.name,
        raw=payload.token,
        server_ids=server_ids,
        scope=payload.scope,
        expires_in_days=payload.expires_in_days,
        created_by="console:import",
        store_raw=True,
    )
    log.info("トークン登録 id=%s name=%r", record.id, payload.name)
    return {"record": record.to_dict()}


@tokens_router.post("/{token_id}/revoke")
def revoke_token(request: Request, token_id: str) -> dict[str, Any]:
    """トークンを失効させる (即座にAgentへの認証が無効化される)。"""
    store: TokenStore = request.app.state.store
    if store.get_token(token_id) is None:
        raise HTTPException(status_code=404, detail=f"トークンが見つかりません: {token_id}")
    revoked = store.revoke_token(token_id)
    return {"revoked": revoked, "record": store.get_token(token_id).to_dict()}


@tokens_router.delete("/{token_id}")
def delete_token(request: Request, token_id: str) -> dict[str, Any]:
    """トークンレコードを完全削除する。"""
    store: TokenStore = request.app.state.store
    if store.get_token(token_id) is None:
        raise HTTPException(status_code=404, detail=f"トークンが見つかりません: {token_id}")
    deleted = store.delete_token(token_id)
    return {"deleted": deleted, "id": token_id}


@tokens_router.post("/{token_id}/rotate")
def rotate_token(request: Request, token_id: str, payload: TokenRotateRequest) -> dict[str, Any]:
    """トークンをローテーションする。

    新しいトークンを発行し、古いトークンはgrace_period_daysの間有効（グラ期間）。
    グラ期間後、古いトークンは自動的に無効化される。
    """
    store: TokenStore = request.app.state.store
    if store.get_token(token_id) is None:
        raise HTTPException(status_code=404, detail=f"トークンが見つかりません: {token_id}")
    client_host = request.client.host if request.client is not None else ""
    try:
        new_record = store.rotate_token(
            token_id,
            grace_period_days=payload.grace_period_days,
            rotated_by=f"console:{client_host}",
            expires_in_days=payload.expires_in_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log.info(
        "トークンローテーション old_id=%s new_id=%s grace_days=%d",
        token_id, new_record.id, payload.grace_period_days,
    )
    return {"token": new_record.token_raw, "record": new_record.to_dict()}


@tokens_router.get("/{token_id}/rotations")
def get_rotation_history(request: Request, token_id: str) -> dict[str, Any]:
    """トークンのローテーション履歴を取得する。"""
    store: TokenStore = request.app.state.store
    if store.get_token(token_id) is None:
        raise HTTPException(status_code=404, detail=f"トークンが見つかりません: {token_id}")
    history = store.get_rotation_history(token_id)
    return {"token_id": token_id, "rotations": history}


@tokens_router.post("/cleanup-grace-periods")
def cleanup_grace_periods(request: Request) -> dict[str, Any]:
    """グラ期間を経過した古いトークンを一括無効化する。"""
    store: TokenStore = request.app.state.store
    count = store.cleanup_expired_grace_periods()
    return {"cleaned": count}



# ---- 承認 (Human Approval) 管理 API ----

from .approvals import (  # noqa: E402
    ApprovalError,
    ApprovalNotFoundError,
    ApprovalRecord,
    ApprovalStore,
)

approvals_router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class ApproveRequest(BaseModel):
    approver: str = Field(default="console", max_length=100, description="承認者名")
    ttl_minutes: int = Field(default=15, ge=1, le=1440, description="承認後の有効期限(分)")


class RejectRequest(BaseModel):
    approver: str = Field(default="console", max_length=100)


def _store_or_503(request: Request) -> ApprovalStore:
    store: ApprovalStore | None = getattr(request.app.state, "approvals", None)
    if store is None:
        raise HTTPException(status_code=503, detail="承認ストアが初期化されていません")
    return store


@approvals_router.get("")
def list_approvals(request: Request, limit: int = 100) -> dict[str, Any]:
    """承認要求の一覧を返す (新しい順)。"""
    store = _store_or_503(request)
    records: list[ApprovalRecord] = store.list(limit=limit)
    return {"approvals": [r.to_dict() for r in records]}


@approvals_router.get("/{approval_id}")
def get_approval(request: Request, approval_id: str) -> dict[str, Any]:
    store = _store_or_503(request)
    rec = store.get(approval_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"承認が見つかりません: {approval_id}")
    return rec.to_dict()


@approvals_router.post("/{approval_id}/approve")
def approve(request: Request, approval_id: str, payload: ApproveRequest) -> dict[str, Any]:
    """pending の承認要求を承認する (ttl_minutes 後に失効)。"""
    store = _store_or_503(request)
    try:
        rec = store.approve(approval_id, approver=payload.approver, ttl_minutes=payload.ttl_minutes)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    log.info("承認 id=%s approver=%r ttl=%s分", approval_id, payload.approver, payload.ttl_minutes)
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        audit.log(actor=f"console:{payload.approver}", action="approve_restart", server=rec.server_id,
                  params={"service": rec.service, "approval_id": approval_id, "ttl_minutes": payload.ttl_minutes}, ok=True)
    return rec.to_dict()


@approvals_router.post("/{approval_id}/reject")
def reject(request: Request, approval_id: str, payload: RejectRequest) -> dict[str, Any]:
    """pending の承認要求を却下する。"""
    store = _store_or_503(request)
    try:
        rec = store.reject(approval_id, approver=payload.approver)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    log.info("承認却下 id=%s approver=%r", approval_id, payload.approver)
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        audit.log(actor=f"console:{payload.approver}", action="reject_restart", server=rec.server_id,
                  params={"service": rec.service, "approval_id": approval_id}, ok=True)
    return rec.to_dict()


@approvals_router.delete("/{approval_id}")
def delete_approval(request: Request, approval_id: str) -> dict[str, Any]:
    """承認レコードを削除する。"""
    store = _store_or_503(request)
    deleted = store.delete(approval_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"承認が見つかりません: {approval_id}")
    return {"deleted": deleted, "id": approval_id}
