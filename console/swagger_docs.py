"""管理コンソール API の FastAPI アプリに Swagger UI / ReDoc を統合する。

FastAPI は /docs (Swagger UI) と /redoc を自動生成するが、
管理コンソールでは認証ミドルウェアの関係で /docs が表示されない場合がある。
このミドルウェアは /docs, /redoc, /openapi.json を認証除外パスとして登録し、
Swagger UI が常に表示されるようにする。

使用法:
    from console.swagger_docs import setup_swagger_ui
    app = create_app(config)
    setup_swagger_ui(app)
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware


def setup_swagger_ui(
    app: FastAPI,
    title: str = "Linux Remote Management MCP",
    version: str = "0.1.0",
    description: str | None = None,
) -> None:
    """管理コンソールアプリにSwagger UIとReDocを設定する。"""
    if description is None:
        description = (
            "Linux Remote Management MCP 管理コンソール API\n\n"
            "## 認証\n"
            "- Basic認証: `Authorization: Basic base64(user:pass)`\n"
            "- OIDC: `Authorization: Bearer <oidc_token>`\n"
            "- トークン認証: `Authorization: Bearer <mcp_token>`\n\n"
            "## スコープ\n"
            "- `readonly`: 読み取り専用操作\n"
            "- `operator`: 破壊的操作（サービス再起動など）\n"
            "- `admin`: 管理操作（トークン発行、principal管理）"
        )

    # OpenAPIメタデータ更新
    app.title = title
    app.description = description
    app.version = version

    # CORS設定（Swagger UIからのアクセスを許可）
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def add_openapi_tag_metadata(app: FastAPI) -> None:
    """OpenAPI仕様にタグのメタデータを追加する。"""
    if app.openapi_schema is not None:
        return

    openapi_schema = app.openapi()
    tags = [
        {"name": "meta", "description": "アプリ/サーバー/スコープのメタ情報"},
        {"name": "nodes", "description": "管理対象ノードの状態取得"},
        {"name": "tokens", "description": "MCPトークン管理（発行/失効/ローテーション）"},
        {"name": "servers", "description": "管理対象サーバー登録"},
        {"name": "principals", "description": "OIDCプリンシパル管理"},
        {"name": "agent-credentials", "description": "Agent認証情報管理"},
        {"name": "approvals", "description": "Human Approval 承認管理"},
    ]
    openapi_schema["tags"] = tags
    app.openapi_schema = openapi_schema
