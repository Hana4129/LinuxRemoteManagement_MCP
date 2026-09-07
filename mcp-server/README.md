# Linux Remote Management MCP Server

AI クライアント (Claude Desktop 等) から **MCP プロトコル** でリモート Linux ノードを管理するサーバー。
管理コンソール (Web UI) は専用Webサーバーとして分離して起動する。

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
│   ├── main.py            # 管理コンソールFastAPI組立て
│   ├── mcp_http.py        # MCP専用FastAPIアプリ
│   └── mcp_http_entry.py  # MCP専用Webサーバー起動エントリポイント
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

### 1. 依存環境インストール

```bash
cd mcp-server
pip install -r requirements.txt
```

### 2. 管理コンソール起動

```bash
python -m app
# → http://127.0.0.1:8080/ で社内管理コンソール

# 別ターミナルでMCP HTTPサーバーを起動
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
      "cwd": "/path/to/mcp-server",
      "env": {
        "LINUX_MCP_TOKEN": "<issued-token>"
      }
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
- トークンは `data/tokens.db` (SQLite) に **SHA256 ハッシュ + 暗号化した生値** (0600) で保存。生値は AES-256-GCM で暗号化され、鍵は DB 外 (`LRM_TOKEN_ENCRYPTION_KEY` 環境変数 or `token_encryption.key`) で管理

### 利用者・Agent credential管理
- `POST /api/principals` — 利用者principalを作成
- `POST /api/principals/{id}/permissions` — server/scope権限を付与
- `DELETE /api/principals/{id}/permissions/{scope}/{server}` — 権限を失効
- `POST /api/principals/{id}/disable` — principalと紐付くMCP tokenを無効化
- `POST /api/agent-credentials` — Agent接続専用credentialを登録
- `POST /api/agent-credentials/{id}/revoke` — Agent credentialを失効

MCP利用者tokenとAgent接続credentialは別管理する。既存tokenは移行互換のためfallbackとして使用される。
Agent credentialの失効はAgentの管理endpointへ同期されるため、`agent.admin_token` とAgent側 `agent.admin_token_hash` を対応させ、管理endpointをmTLS/Private Network内に限定する。

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

# ターミナル2: 管理コンソール起動
python -m app
# → http://127.0.0.1:8080/ でノード一覧を確認

# ターミナル3: MCP HTTP起動 (必要な場合)
python -m app.mcp_http_entry
```

`config.yml` の `servers` に登録されたノードの `url` に対して、
コンソールは自動的に発行済みトークンを Bearer 認証として付与し `GET /v1/health` を呼び出します。

### トークン発行 (CLI)

```bash
python -c "
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
  auth_required: true
  auth_mode: basic         # oidc を使う場合は下記OIDC設定も必須
  # username: admin
  # password: change-me
  # oidc_issuer: https://idp.example.internal/realms/company
  # oidc_audience: linux-remote-management
  # oidc_jwks_url: https://idp.example.internal/realms/company/protocol/openid-connect/certs
  # レート制限 (IP+トークン複合・操作別)。0 なら基本値へフォールバック
  rate_limit_per_minute: 60
  rate_limit_burst: 10
  # rate_limit_write_per_minute: 20   # 操作系 (POST/PUT/PATCH/DELETE) の別バケット
  # rate_limit_write_burst: 5
  # rate_limit_token_per_minute: 120  # Bearer トークン単位の分離バケット
  # rate_limit_token_burst: 30

mcp:
  host: 127.0.0.1
  port: 8090
  path: /
  enabled: true
  stdio_token_env: LINUX_MCP_TOKEN

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

- トークンは CSPRNG (64バイト) で生成、SHA256 ハッシュで照合
- 生トークンは DB に平文保存しない (AES-256-GCM で保存時暗号化、鍵は DB 外で管理)
- `data/tokens.db` はファイルパーミッション 0600
- Agent への通信は **Bearer Token** 認証 (constant-time 比較)
- 本番では Secret Store (Vault 等) との連携への置き換えを推奨
  (`LRM_TOKEN_ENCRYPTION_KEY` を KMS/Vault から注入することで鍵管理を外部化できる)
- 社内ネットワークでのみアクセス可能なホスト (127.0.0.1) で listen

### 設定ファイルの機密情報保護 (Config Secret References)

`config.yml` のシークレット (`console.password`, `console.siem_api_key`,
`console.oidc_client_secret`, `agent.admin_token`, `agent.client_cert`,
`agent.client_key`) は **環境変数参照** (`${ENV_VAR}` または `${ENV_VAR:-default}`)
の形式で指定できる。読み込み時に環境変数の値に展開され、`save()` 時には
参照形式がそのまま config.yml に書き戻されるため、シークレットが平文で
ファイルへ永続化されることはない。

```yaml
console:
  # 実際の値は環境変数で提供。設定ファイルには参照を保持。
  password: ${LINUX_MCP_CONSOLE_PASS}
  siem_api_key: ${MCP_SIEM_API_KEY:-}   # :- で空デフォルト
agent:
  admin_token: ${LINUX_MCP_AGENT_ADMIN_TOKEN}
```

- 未設定の環境変数は **fail-closed** で `ValueError` (デフォルト値 `:-` ありの場合は空文字)
- `scripts/env.example` を参考に `/etc/linux-mcp-server/env` (chmod 600) へ配置し、
  systemd の `EnvironmentFile` で読み込む (§1.4 参照)
- `LINUX_MCP_CONSOLE_USER` / `LINUX_MCP_CONSOLE_PASS` は `console.username` /
  `console.password` の fallback としても使用可能

### レート制限 (IP + トークン複合・操作別)

コンソールと MCP HTTP の両方にトークンバケット方式のレート制限が適用される
(`app/mcp_ratelimit.py` の `install_rate_limit`)。

- **基本バケット**: IP、もしくは `IP+Bearerトークンハッシュ` の複合キーで計上
  (同一 NAT 配下でも別トークンは独立にカウントされる)
- **操作系バケット**: `POST/PUT/PATCH/DELETE` は独立した上限 (`rate_limit_write_*`) で制限
- **トークンバケット**: Bearer トークン単位の上限 (`rate_limit_token_*`) で制限
- キーには生トークンではなく **SHA-256 ハッシュ** のみを使う
- 超過時は `429 Too Many Requests` + `Retry-After: 60`

```yaml
console:
  rate_limit_per_minute: 60
  rate_limit_burst: 10
  rate_limit_write_per_minute: 20   # 操作系の分離 (0=基本値へフォールバック)
  rate_limit_write_burst: 5
  rate_limit_token_per_minute: 120  # トークン単位の分離 (0=基本値へフォールバック)
  rate_limit_token_burst: 30
```

### 監査ログのハッシュチェーン (Immutable Audit Log)

`data/mcp_audit.jsonl` の各エントリは SHA-256 の **ハッシュチェーン** で連結されている。
`prev_hash` が1つ前のエントリのハッシュを指し、末尾のハッシュは次エントリの入力に含まれる。
1エントリでも改ざんすると以降のチェーン全体が破綻するため、改ざんを検知できる
(Agent 側 `lrm-mcp-agent/internal/audit/logger.go` と同じ方式)。

検証コマンド:

```bash
python -m app.verify_audit_log data/mcp_audit.jsonl
# すべて正常: OK
# 改ざん/破綻あり: FAIL + 問題行の一覧、終了コード 1
```

- 旧形式 (hash フィールドなし) のエントリは検証対象外としてスキップする
- ローテーションで前のファイルを参照する先頭エントリの `prev_hash` は許容する

本番では監査ログを **append-only** で保持することを推奨する
(例: `sudo mount -o remount,ro /var/lib/linux-mcp` や、`chattr +a` による追記専用化)。