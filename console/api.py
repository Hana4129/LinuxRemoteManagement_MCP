"""管理コンソール HTTP API。

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
- POST /api/agent-credentials           Agent credential登録 (Agent側生成token)
- POST /api/agent-credentials/generate  Agent credential生成 (サーバー側で発行、生値は一度だけ返す)
- POST /api/agent-credentials/{id}/revoke  失効 (Agent失効同期つき)
- POST /api/agent-credentials/{id}/rotate  ローテーション (グラ期間つき)
- GET  /api/agent-credentials/{id}/rotations  ローテーション履歴
- POST /api/agent-credentials/cleanup-grace-periods  グラ期間経過credential一括無効化
"""

from __future__ import annotations

import logging
import os
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .auth import current_principal
from app.agent_client import AgentClient, AgentResult
from app.config import ServerConfig
from app.db import TokenStore
from app.status import collect_all_nodes, collect_node_status, summarize_nodes
from app.tokens import SCOPES, now_iso

log = logging.getLogger(__name__)


def _require_admin(request: Request) -> None:
    principal = current_principal()
    if principal is not None and principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="管理者権限が必要です")


ENV_TOKEN_PREFIX = "env:"


def _resolve_agent_token(value: str) -> str:
    """`env:NAME` 形式なら環境変数から解決する (Secret Manager連携の踏み台)。

    CI/CD のシークレット注入 (Vaultエージェント等) で環境変数に格納した
    トークンを、生値をAPIリクエストへ載せずに登録できる。
    環境変数が未設定・空の場合は 400 を返す。
    """
    token = value.strip()
    if not token.startswith(ENV_TOKEN_PREFIX):
        return token
    env_name = token[len(ENV_TOKEN_PREFIX):].strip()
    if not env_name:
        raise HTTPException(status_code=400, detail="env: の後に環境変数名を指定してください")
    resolved = os.environ.get(env_name)
    if not resolved:
        raise HTTPException(status_code=400, detail=f"環境変数が未設定または空です: {env_name}")
    return resolved


def _approval_actor(request: Request, fallback: str) -> str:
    principal = current_principal()
    if principal is not None:
        return str(principal.get("subject") or principal.get("id") or "oidc")
    return fallback


def _reject_self_approval(rec: ApprovalRecord, approver: str) -> None:
    """要求者と承認者が同一の場合は自己承認を禁止する (4-eyes 原則)。"""
    requester = (rec.requested_by or "").strip()
    if requester and approver and requester == approver:
        raise HTTPException(
            status_code=400,
            detail="要求者と承認者が同一のため自己承認はできません",
        )


def _audit_actor() -> str:
    principal = current_principal()
    if principal is None:
        return "unknown"
    return str(principal.get("subject") or principal.get("id") or "authenticated")


def _audit_management(request: Request, action: str, params: dict[str, Any], *, ok: bool = True) -> None:
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        audit.log(actor=f"console:{_audit_actor()}", action=action, params=params, ok=ok)

meta_router = APIRouter(prefix="/api", tags=["meta"])
nodes_router = APIRouter(prefix="/api/nodes", tags=["nodes"])
tokens_router = APIRouter(prefix="/api/tokens", tags=["tokens"])
servers_router = APIRouter(prefix="/api/servers", tags=["servers"])
principals_router = APIRouter(prefix="/api/principals", tags=["principals"])
agent_credentials_router = APIRouter(prefix="/api/agent-credentials", tags=["agent-credentials"])


class TokenCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="トークンの説明・用途")
    scope: Literal["readonly", "operator"]
    server_ids: list[str] = Field(..., min_length=1, description='アクセス許可するサーバーID ("*" で全許可)')
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="有効期限(日)。未指定=無期限")
    principal_id: str | None = Field(default=None, description="紐付けるMCP principal")


class PrincipalCreateRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    display_name: str = Field(..., min_length=1, max_length=200)
    role: Literal["admin", "operator", "viewer"] = "viewer"


class PermissionRequest(BaseModel):
    server_id: str = Field(..., min_length=1, max_length=100)
    scope: Literal["readonly", "operator"]


class AgentCredentialCreateRequest(BaseModel):
    server_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=100)
    token: str = Field(..., min_length=1, description="Agent側に設定済みのBearer token")
    agent_token_id: str = Field(..., min_length=1, max_length=100, description="Agent設定内のtoken id")
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class AgentCredentialGenerateRequest(BaseModel):
    """サーバー側でAgent credentialを生成するリクエスト (秘密値の手入力不要)。"""

    server_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=100)
    agent_token_id: str = Field(..., min_length=1, max_length=100, description="Agent設定内のtoken id")
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class AgentCredentialRotateRequest(BaseModel):
    grace_period_days: int = Field(default=7, ge=1, le=90, description="新旧credentialのグラ期間(日)")
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="新しいcredentialの有効期限(日)")


class TokenRotateRequest(BaseModel):
    grace_period_days: int = Field(default=7, ge=1, le=90, description="新旧トークンのグラ期間(日)")
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="新しいトークンの有効期限(日)")


class TokenImportRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    token: str = Field(..., min_length=1, description="登録する生トークン")
    server_ids: list[str] = Field(..., min_length=1)
    scope: Literal["readonly", "operator"]
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    principal_id: str | None = Field(default=None)


class ServerAddRequest(BaseModel):
    """管理コンソールから新規ノードを追加するリクエスト。"""
    id: str = Field(..., min_length=1, max_length=100, description="サーバーID (英数字とハイフンのみ)")
    name: str = Field(..., min_length=1, max_length=200, description="表示名")
    url: str = Field(..., min_length=1, max_length=2000, description="Agent の Base URL (https://host:9443)")
    env: str = Field(default="development", description="環境 (development/staging/production)")
    description: str = Field(default="", max_length=1000, description="説明")
    issue_token: bool = Field(default=False, description="追加と同時にトークンを発行するか")
    token_name: str | None = Field(default=None, max_length=100, description="トークン名 (issue_token=true時)")
    token_scope: Literal["readonly", "operator"] = Field(default="readonly", description="トークンスコープ")
    token_expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="トークン有効期限(日)")


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
            "http_enabled": cfg.mcp.enabled,
            "http_host": cfg.mcp.host,
            "http_port": cfg.mcp.port,
            "http_path": cfg.mcp.path,
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
        principal_id=payload.principal_id,
    )
    _audit_management(
        request,
        "issue_mcp_token",
        {"token_id": record.id, "principal_id": payload.principal_id, "scope": payload.scope, "server_ids": server_ids},
    )
    log.info("トークン発行 id=%s name=%r scope=%s servers=%s", record.id, payload.name, payload.scope, server_ids)
    return {"token": raw, "record": record.to_dict()}


# ---- principals / permissions ----
@principals_router.get("")
def list_principals(request: Request) -> dict[str, Any]:
    store: TokenStore = request.app.state.store
    return {"principals": store.list_principals()}


@principals_router.post("")
def create_principal(request: Request, payload: PrincipalCreateRequest) -> dict[str, Any]:
    _require_admin(request)
    store: TokenStore = request.app.state.store
    try:
        principal = store.create_principal(payload.subject, payload.display_name, payload.role)
    except Exception as exc:  # noqa: BLE001 - duplicate subject is a client error
        raise HTTPException(status_code=409, detail=f"principalを作成できません: {exc}") from exc
    _audit_management(request, "create_principal", {"principal_id": principal["id"], "subject": payload.subject, "role": payload.role})
    return principal


@principals_router.get("/{principal_id}/permissions")
def list_permissions(request: Request, principal_id: str) -> dict[str, Any]:
    store: TokenStore = request.app.state.store
    if store.get_principal(principal_id) is None:
        raise HTTPException(status_code=404, detail=f"principalが見つかりません: {principal_id}")
    return {"permissions": store.list_permissions(principal_id)}


@principals_router.post("/{principal_id}/permissions")
def grant_permission(request: Request, principal_id: str, payload: PermissionRequest) -> dict[str, Any]:
    _require_admin(request)
    store: TokenStore = request.app.state.store
    if store.get_principal(principal_id) is None:
        raise HTTPException(status_code=404, detail=f"principalが見つかりません: {principal_id}")
    _validate_server_ids(request, [payload.server_id] if payload.server_id != "*" else ["*"])
    store.grant_permission(principal_id, payload.server_id, payload.scope)
    _audit_management(request, "grant_permission", {"principal_id": principal_id, "server_id": payload.server_id, "scope": payload.scope})
    return {"granted": True, "principal_id": principal_id, **payload.model_dump()}


@principals_router.delete("/{principal_id}/permissions/{scope}/{server_id}")
def revoke_permission(request: Request, principal_id: str, scope: str, server_id: str) -> dict[str, Any]:
    _require_admin(request)
    if scope not in SCOPES:
        raise HTTPException(status_code=400, detail=f"不正なscope: {scope}")
    store: TokenStore = request.app.state.store
    if store.get_principal(principal_id) is None:
        raise HTTPException(status_code=404, detail=f"principalが見つかりません: {principal_id}")
    revoked = store.revoke_permission(principal_id, server_id, scope)
    _audit_management(request, "revoke_permission", {"principal_id": principal_id, "server_id": server_id, "scope": scope, "revoked": revoked})
    return {"revoked": revoked}


@principals_router.post("/{principal_id}/disable")
def disable_principal(request: Request, principal_id: str) -> dict[str, Any]:
    _require_admin(request)
    store: TokenStore = request.app.state.store
    if store.get_principal(principal_id) is None:
        raise HTTPException(status_code=404, detail=f"principalが見つかりません: {principal_id}")
    disabled = store.disable_principal(principal_id)
    _audit_management(request, "disable_principal", {"principal_id": principal_id, "disabled": disabled})
    return {"disabled": disabled, "principal_id": principal_id}


@agent_credentials_router.post("")
def register_agent_credential(request: Request, payload: AgentCredentialCreateRequest) -> dict[str, Any]:
    _require_admin(request)
    _server_or_404(request, payload.server_id)
    store: TokenStore = request.app.state.store
    token = _resolve_agent_token(payload.token)
    credential = store.create_agent_credential(
        payload.server_id, payload.name, token, expires_in_days=payload.expires_in_days
        , agent_token_id=payload.agent_token_id
    )
    _audit_management(request, "register_agent_credential", {"credential_id": credential.id, "server_id": payload.server_id, "agent_token_id": payload.agent_token_id})
    return {"credential": credential.to_dict()}


@agent_credentials_router.post("/generate")
def generate_agent_credential(request: Request, payload: AgentCredentialGenerateRequest) -> dict[str, Any]:
    """Agent credentialをサーバー側で生成する (発行フローの標準化)。

    生tokenを手入力せず、CSPRNGで生成する。生値はレスポンスに一度だけ返し、
    Agent側のconfig.ymlへ配布する。一覧には生値を再表示しない。
    """
    _require_admin(request)
    _server_or_404(request, payload.server_id)
    store: TokenStore = request.app.state.store
    credential, raw = store.generate_agent_credential(
        server_id=payload.server_id,
        name=payload.name,
        agent_token_id=payload.agent_token_id,
        expires_in_days=payload.expires_in_days,
    )
    _audit_management(
        request,
        "generate_agent_credential",
        {"credential_id": credential.id, "server_id": payload.server_id, "agent_token_id": payload.agent_token_id},
    )
    return {"credential": credential.to_dict(), "token": raw}


@agent_credentials_router.get("")
def list_agent_credentials(request: Request) -> dict[str, Any]:
    store: TokenStore = request.app.state.store
    return {"credentials": [credential.to_dict() for credential in store.list_agent_credentials()]}


def _sync_revocation_to_agent(request: Request, server: ServerConfig, agent_token_id: str) -> tuple[bool, str]:
    """Agentの管理失効endpointへ失効要求を同期する。

    戻り値は (同期済みか, 詳細メッセージ)。HTTP 404 は「Agent上に該当tokenが
    存在しない (失効済みまたは未登録)」として同期成功とみなし、
    同じ失効要求の再送に対する冪等性を保証する。
    """
    import httpx

    cfg = request.app.state.config
    try:
        response = httpx.post(
            server.url.rstrip("/") + "/v1/admin/tokens/" + agent_token_id + "/revoke",
            headers={"X-LRM-Admin-Token": cfg.agent.admin_token},
            verify=cfg.agent.tls_verify,
            timeout=cfg.agent.timeout_seconds,
        )
    except httpx.HTTPError as exc:
        return False, str(exc)
    if response.status_code in (200, 202, 204):
        return True, "ok"
    if response.status_code == 404:
        return True, "already-revoked-or-missing"
    return False, f"HTTP {response.status_code}"


@agent_credentials_router.post("/{credential_id}/revoke")
def revoke_agent_credential(request: Request, credential_id: str) -> dict[str, Any]:
    """Agent credentialを失効する (fail-closed)。

    Agentへの失効同期に失敗した場合 (Agent停止中など) でも、MCP Server側では
    即座にcredentialを無効化し、sync_state=pending として記録する。Agent復旧後に
    /api/agent-credentials/{id}/resync または /api/agent-credentials/resync-pending
    で再送する。
    """
    _require_admin(request)
    store: TokenStore = request.app.state.store
    credential = store.get_agent_credential(credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail=f"Agent credentialが見つかりません: {credential_id}")
    if not credential.agent_token_id or not request.app.state.config.agent.admin_token:
        # Agent失効同期の対象外: ローカル失効のみ実施する
        revoked = store.revoke_agent_credential(credential_id)
        store.set_agent_credential_sync_state(credential_id, "skipped")
        _audit_management(
            request,
            "revoke_agent_credential",
            {"credential_id": credential_id, "agent_token_id": credential.agent_token_id, "agent_synced": False, "sync_state": "skipped", "revoked": revoked},
        )
        return {"revoked": revoked, "id": credential_id, "agent_synced": False, "sync_state": "skipped"}
    server = _server_or_404(request, credential.server_id)
    synced, detail = _sync_revocation_to_agent(request, server, credential.agent_token_id)
    # fail-closed: 同期成否にかかわらずローカルは必ず失効させる
    revoked = store.revoke_agent_credential(credential_id)
    sync_state = "synced" if synced else "pending"
    store.set_agent_credential_sync_state(credential_id, sync_state)
    _audit_management(
        request,
        "revoke_agent_credential",
        {"credential_id": credential_id, "agent_token_id": credential.agent_token_id, "agent_synced": synced, "sync_state": sync_state, "revoked": revoked, "sync_detail": detail},
    )
    payload: dict[str, Any] = {"revoked": revoked, "id": credential_id, "agent_synced": synced, "sync_state": sync_state}
    if not synced:
        payload["sync_detail"] = detail
        return JSONResponse(status_code=202, content=payload)
    return payload


@agent_credentials_router.post("/resync-pending")
def resync_pending_agent_credential_revocations(request: Request) -> dict[str, Any]:
    """Agent停止中等でpendingになっている失効をAgentへ一括再送する。

    Agent復旧後に管理コンソール、systemd timer、cronなどから呼び出すことを想定。
    同じ失効要求を複数回送信してもAgent側は冪等に処理される
    (404は「既に失効済みまたは未登録」として同期成功扱い)。
    """
    _require_admin(request)
    store: TokenStore = request.app.state.store
    results: list[dict[str, Any]] = []
    for credential in store.list_pending_revocation_syncs():
        server = request.app.state.config.server(credential.server_id)
        if server is None:
            results.append(
                {
                    "id": credential.id,
                    "server_id": credential.server_id,
                    "agent_token_id": credential.agent_token_id,
                    "synced": False,
                    "sync_state": "pending",
                    "detail": f"server設定が見つかりません: {credential.server_id}",
                }
            )
            continue
        synced, detail = _sync_revocation_to_agent(request, server, credential.agent_token_id)
        if synced:
            store.set_agent_credential_sync_state(credential.id, "synced")
        results.append(
            {
                "id": credential.id,
                "server_id": credential.server_id,
                "agent_token_id": credential.agent_token_id,
                "synced": synced,
                "sync_state": "synced" if synced else "pending",
                "detail": detail,
            }
        )
    _audit_management(
        request,
        "resync_pending_agent_credentials",
        {"attempted": len(results), "synced": sum(1 for r in results if r["synced"])},
    )
    return {"results": results, "remaining_pending": len(store.list_pending_revocation_syncs())}


@agent_credentials_router.post("/{credential_id}/resync")
def resync_agent_credential_revocation(request: Request, credential_id: str) -> dict[str, Any]:
    """単一credentialのpending失効をAgentへ再送する。"""
    _require_admin(request)
    store: TokenStore = request.app.state.store
    credential = store.get_agent_credential(credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail=f"Agent credentialが見つかりません: {credential_id}")
    if not credential.agent_token_id or not request.app.state.config.agent.admin_token:
        raise HTTPException(status_code=503, detail="Agent失効同期用のcredential設定がありません")
    if credential.enabled:
        raise HTTPException(status_code=409, detail="credentialは失効していないためresync対象外です")
    server = _server_or_404(request, credential.server_id)
    synced, detail = _sync_revocation_to_agent(request, server, credential.agent_token_id)
    if not synced:
        _audit_management(
            request,
            "resync_agent_credential_revocation",
            {"credential_id": credential_id, "agent_token_id": credential.agent_token_id, "synced": False, "sync_detail": detail},
        )
        raise HTTPException(status_code=502, detail=f"Agent失効同期に失敗しました: {detail}")
    store.set_agent_credential_sync_state(credential_id, "synced")
    _audit_management(
        request,
        "resync_agent_credential_revocation",
        {"credential_id": credential_id, "agent_token_id": credential.agent_token_id, "synced": True},
    )
    return {"id": credential_id, "agent_token_id": credential.agent_token_id, "synced": True, "sync_state": "synced"}


@agent_credentials_router.post("/{credential_id}/rotate")
def rotate_agent_credential(request: Request, credential_id: str, payload: AgentCredentialRotateRequest) -> dict[str, Any]:
    """Agent credentialをローテーションする (グラ期間つき)。

    新しいcredentialを生成し、生値を一度だけ返す。旧credentialは
    grace_period_daysの間グラ期間として残り、期間経過後は使用不可
    (active=False)。/api/agent-credentials/cleanup-grace-periods で
    完全失効 (enabled=0) させる。
    """
    _require_admin(request)
    store: TokenStore = request.app.state.store
    if store.get_agent_credential(credential_id) is None:
        raise HTTPException(status_code=404, detail=f"Agent credentialが見つかりません: {credential_id}")
    try:
        new_credential, raw = store.rotate_agent_credential(
            credential_id,
            grace_period_days=payload.grace_period_days,
            rotated_by=_audit_actor(),
            expires_in_days=payload.expires_in_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    old_credential = store.get_agent_credential(credential_id)
    _audit_management(
        request,
        "rotate_agent_credential",
        {
            "old_credential_id": credential_id,
            "new_credential_id": new_credential.id,
            "server_id": new_credential.server_id,
            "grace_period_days": payload.grace_period_days,
        },
    )
    log.info(
        "Agent credentialローテーション old_id=%s new_id=%s grace_days=%d",
        credential_id, new_credential.id, payload.grace_period_days,
    )
    return {
        "token": raw,
        "credential": new_credential.to_dict(),
        "old_credential": old_credential.to_dict() if old_credential else None,
    }


@agent_credentials_router.get("/{credential_id}/rotations")
def get_agent_credential_rotation_history(request: Request, credential_id: str) -> dict[str, Any]:
    """Agent credentialのローテーション履歴を取得する。"""
    _require_admin(request)
    store: TokenStore = request.app.state.store
    if store.get_agent_credential(credential_id) is None:
        raise HTTPException(status_code=404, detail=f"Agent credentialが見つかりません: {credential_id}")
    return {"credential_id": credential_id, "rotations": store.get_agent_credential_rotations(credential_id)}


@agent_credentials_router.post("/cleanup-grace-periods")
def cleanup_agent_credential_grace_periods(request: Request) -> dict[str, Any]:
    """グラ期間を経過した旧Agent credentialを一括無効化する (完全失効)。"""
    _require_admin(request)
    store: TokenStore = request.app.state.store
    count = store.disable_expired_grace_agent_credentials()
    if count:
        _audit_management(request, "cleanup_agent_credential_grace_periods", {"cleaned": count})
    return {"cleaned": count}


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
        principal_id=payload.principal_id,
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


# ---- servers (nodes management) ----
import re as _re

_SERVER_ID_RE = _re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_]*$")


def _validate_server_id(server_id: str) -> None:
    if not _SERVER_ID_RE.match(server_id):
        raise HTTPException(
            status_code=400,
            detail="サーバーIDは英数字、ハイフン、アンダースコアのみ使用可能です (先頭は英数字)",
        )


@servers_router.get("")
def list_servers(request: Request) -> dict[str, Any]:
    """登録されている管理対象ノードの一覧を返す。"""
    cfg = request.app.state.config
    return {
        "servers": [
            {"id": s.id, "name": s.name, "url": s.url, "env": s.env, "description": s.description}
            for s in cfg.servers
        ]
    }


@servers_router.post("")
def add_server(request: Request, payload: ServerAddRequest) -> dict[str, Any]:
    """新しい管理対象ノードを追加する (config.ymlに永続化)。"""
    _validate_server_id(payload.id)
    cfg: "AppConfig" = request.app.state.config

    # ID重複チェック
    if cfg.server(payload.id) is not None:
        raise HTTPException(
            status_code=409,
            detail=f"サーバーIDが既に登録済みです: {payload.id}",
        )

    # URL形式チェック
    if not payload.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URLは http:// または https:// で始まる必要があります",
        )

    new_server = ServerConfig(
        id=payload.id,
        name=payload.name,
        url=payload.url.rstrip("/"),
        env=payload.env,
        description=payload.description,
    )

    new_cfg = cfg.add_server(new_server)
    new_cfg.save()

    # アプリの設定を更新 (in-memory)
    request.app.state.config = new_cfg

    log.info("サーバー追加 id=%s name=%r url=%s env=%s", payload.id, payload.name, payload.url, payload.env)

    result: dict[str, Any] = {"server": new_server.to_yaml_dict(), "token": None}

    # トークン同時発行
    if payload.issue_token:
        client_host = request.client.host if request.client is not None else ""
        token_name = payload.token_name or f"token-for-{payload.id}"
        record, raw = request.app.state.store.create_token(
            name=token_name,
            server_ids=[payload.id],
            scope=payload.token_scope,
            expires_in_days=payload.token_expires_in_days,
            created_by=f"console:{client_host}",
        )
        result["token"] = raw
        result["token_record"] = record.to_dict()
        log.info("ノード追加に伴うトークン発行 id=%s token_id=%s", payload.id, record.id)

    return result


@servers_router.delete("/{server_id}")
def delete_server(request: Request, server_id: str) -> dict[str, Any]:
    """管理対象ノードを削除する (config.ymlから削除 + 関連トークンの失効)。"""
    cfg: "AppConfig" = request.app.state.config
    if cfg.server(server_id) is None:
        raise HTTPException(status_code=404, detail=f"サーバーが見つかりません: {server_id}")

    # 関連するトークンを失効
    store: TokenStore = request.app.state.store
    tokens = store.list_tokens()
    revoked = []
    for t in tokens:
        if server_id in t.server_ids or "*" in t.server_ids:
            store.revoke_token(t.id)
            revoked.append(t.id)

    new_cfg = cfg.remove_server(server_id)
    new_cfg.save()
    request.app.state.config = new_cfg

    log.info("サーバー削除 id=%s (revoked_tokens=%s)", server_id, revoked)
    return {"deleted": True, "id": server_id, "revoked_tokens": revoked}






# ---- 承認 (Human Approval) 管理 API ----

from app.approvals import (  # noqa: E402
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
)

approvals_router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class ApproveRequest(BaseModel):
    ttl_minutes: int = Field(default=15, ge=1, le=1440, description="承認後の有効期限(分)")


class RejectRequest(BaseModel):
    pass


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
    """pending の承認要求を承認する (ttl_minutes 後に失効)。

    要求者と同一 principal による自己承認は 4-eyes 原則のため禁止する。
    """
    store = _store_or_503(request)
    existing = store.get(approval_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"承認が見つかりません: {approval_id}")
    approver = _approval_actor(request, "console")
    _reject_self_approval(existing, approver)
    try:
        rec = store.approve(approval_id, approver=approver, ttl_minutes=payload.ttl_minutes)
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    log.info("承認 id=%s approver=%r ttl=%s分", approval_id, approver, payload.ttl_minutes)
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        audit.log(actor=f"console:{approver}", action="approve_restart", server=rec.server_id,
                  params={"service": rec.service, "approval_id": approval_id, "ttl_minutes": payload.ttl_minutes}, ok=True)
    return rec.to_dict()


@approvals_router.post("/{approval_id}/reject")
def reject(request: Request, approval_id: str, payload: RejectRequest) -> dict[str, Any]:
    """pending の承認要求を却下する。要求者自身では却下できない。"""
    store = _store_or_503(request)
    existing = store.get(approval_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"承認が見つかりません: {approval_id}")
    approver = _approval_actor(request, "console")
    _reject_self_approval(existing, approver)
    try:
        rec = store.reject(approval_id, approver=approver)
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    log.info("承認却下 id=%s approver=%r", approval_id, approver)
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        audit.log(actor=f"console:{approver}", action="reject_restart", server=rec.server_id,
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
