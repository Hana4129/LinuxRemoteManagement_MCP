# Linux Remote Management MCP Server

AI クライアント (Claude Desktop 等) から **MCP プロトコル** でリモート Linux ノードを管理するサーバー。
社内管理コンソール (Web UI) も同梱。

## 構成

```
mcp-server/
├── app/
│   ├── __init__.py        # パッケージ定義 + __version__
│   ├── __main__.py        # コンソール起動エントリポイント (python -m app)
│   ├── config.py          # config.yml → AppConfig 読み込み
│   ├── tokens.py          # トークン生成/ハッシュ/ユーティリティ
│   ├── db.py              # SQLite トークンストア (0600)
│   ├── agent_client.py    # Linux Agent HTTP クライアント
│   ├── status.py          # ノード状況集納
│   ├── api.py             # 管理コンソール HTTP API
│   ├── mcp_server.py      # FastMCP アプリ (MCP Tools)
│   ├── mcp_entry.py       # MCP stdio エントリポイント
│   ├── main.py            # FastAPI アプリ組立て
│   └── mcp_http_entry.py  # MCP streamable HTTP エントリポイント
├── tools/
│   └── mock_agent.py      # 開発/テスト用モック Linux Agent
├── templates/
│   └── index.html         # 管理コンソール画面
├── static/
│   ├── style.css          # コンソールスタイル
│   └── app.js             # コンソール UI ロジック (vanilla JS)
├── config.yml             # サーバー/コンソール/Agent設定
├── requirements.txt
├── pyproject.toml
└── data/                  # tokens.db はここに生成 (Git除外)
```

## クイックスタート

### 1. 依存環境

**MCP Server (Python):**
```bash
cd mcp-server
pip install -r requirements.txt
```

**Linux Agent (Go 1.22+):**
```bash
# Goが未インストールの場合 (Linux)
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 確認
go version
```

### 2. 管理コンソールとMCP HTTPサーバー起動

```bash
python -m app
# → http://127.0.0.1:8080/ で社内管理コンソール

# 別プロセスで起動
python -m app.mcp_http_entry
# → http://127.0.0.1:8090/ で MCP streamable HTTP
```

### 3. MCP (stdio) クライアント設定

`claude_desktop_config.json` に以下を追加:

```json
{
  "mcpServers": {
    "linux-remote-management": {
      "command": "python -m app.mcp_entry",
      "cwd": "/path/to/mcp-server"
    }
  }
}
```

## 管理コンソール機能

### ノード一覧
- 各ノードの **インストール状況** (running / auth_error / not_responding / unreachable / no_token)
- **OSバージョン** / **カーネル** / **ホスト名** / **稼働時間**
- **Agent バージョン** / **レイテンシ**
- 30秒間隔の自動リフレッシュ

### MCP トークン管理
- **発行**: `POST /api/tokens` — 生トークンを一度だけ返す
- **登録**: `POST /api/tokens/import` — 外部で発行済みトークンを登録
- **失効**: `POST /api/tokens/{id}/revoke` — 即座に Agent 認証無効化
- **削除**: `DELETE /api/tokens/{id}`
- トークンは `data/tokens.db` (SQLite) に **SHA256 ハッシュ + 生値** (0600) で保存

### API エンドポイント

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/meta` | アプリ/サーバー/スコープメタ |
| GET | `/api/nodes` | ノード一覧 (Agent を並行呼び出し) |
| GET | `/api/nodes/{id}` | ノード詳細 (system / disk / プロセス数) |
| GET | `/api/nodes/{id}/disk` | ディスク使用状況 |
| GET | `/api/nodes/{id}/processes` | プロセス一覧 |
| GET | `/api/tokens` | トークン一覧 (生値非表示) |
| POST | `/api/tokens` | トークン発行 (生値一度だけ返す) |
| POST | `/api/tokens/import` | 外部発行トークン登録 |
| POST | `/api/tokens/{id}/revoke` | トークン失効 |
| DELETE | `/api/tokens/{id}` | トークン削除 |

## 開発/テスト

### モック Agent での E2E テスト

```bash
# ターミナル1: モック Agent 起動 (8443)
python -m tools.mock_agent --port 8443 --hostname dev-web-01 --token dev-token

# ターミナル2: コンソール起動
python -m app
# → http://127.0.0.1:8080/ でノード一覧を確認
```

`config.yml` の `servers` に登録されたノードの `url` に対して、
コンソールは自動的に発行済みトークンを Bearer 認証として付与し `GET /v1/health` を呼び出します。

### トークン発行 (console上でも可能)

```bash
# CLI でトークン発行
python -c "
from app.config import load_config
from app.db import TokenStore
from app.main import create_app
app = create_app()
store = app.state.store
record, raw = store.create_token(name='cli', server_ids=['*'], scope='readonly')
print('ID:', record.id)
print('Token:', raw)
"
```

## 設定 (config.yml)

```yaml
console:
  host: 127.0.0.1
  port: 8080
  data_dir: ./data
  mcp_http: true
  # username: admin       # Basic認証を有効化 (任意)
  # password: change-me

agent:
  timeout_seconds: 3
  tls_verify: true

servers:
  - id: prod-web-01
    name: "本番 Web #01"
    url: https://prod-web-01.internal:8443
    env: production
```

## セキュリティ

- トークンは CSPRNG (64バイト) で生成、SHA256 ハッシュで保存
- `data/tokens.db` はファイルパーミッション 0600
- Agent への通信は **Bearer Token** 認証 (constant-time 比較)
- 本番では Secret Store (Vault 等) との連携への置き換えを推奨
- 社内ネットワークでのみアクセス可能なホスト (127.0.0.1) で listen

## ライセンス

MIT