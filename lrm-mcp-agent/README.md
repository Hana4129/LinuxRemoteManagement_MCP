# Linux Agent (Go)

Linux Remote Management Agent - Go implementation.

## Prerequisites

- **Go 1.22 or later** must be installed.

### Installing Go on Linux

```bash
# Download (check https://go.dev/dl/ for the latest version)
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz

# Remove any existing Go installation
sudo rm -rf /usr/local/go

# Extract to /usr/local
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz

# Add to PATH (add to ~/.bashrc or ~/.profile for persistence)
export PATH=$PATH:/usr/local/go/bin

# Verify installation
go version
```

> If Go is installed but not found in PATH, restart your terminal or run `source ~/.bashrc`.

## Architecture

```
MCP Server ──HTTPS + Bearer Token──> Linux Agent ──Dedicated User──> OS
```

## Features

- HTTPS/TLS 1.2+ with auto-generated self-signed certificates
- Bearer Token authentication (SHA-256 hash comparison, constant-time)
- Policy-based authorization (readonly/operator scope)
- Allowlist-based access control (deny by default)
- Structured API (no shell exposure for MVP operations)
- JSON audit logging
- Rate limiting per client IP

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /v1/health | Health check (認証不要) |
| GET | /v1/system | System info (hostname, OS, kernel, uptime, memory) |
| GET | /v1/disk | Disk usage (df-based) |
| GET | /v1/processes | Process list (ps-based, max 100) |
| GET | /v1/services/{name} | Service status (systemctl is-active) |
| POST | /v1/services/{name}/restart | Restart service (operator scope。MCP Server側で人間の承認が必要) |
| GET | /v1/services/{name}/logs | Service logs (journalctl) |
| GET | /v1/files?path=... | Read file (allowlist + denied list) |
| POST | /v1/execute | Execute command (allowlist, operator scope) |
| GET | /v1/admin/tokens | トークン一覧 (id/name/scope/disabled のみ。hash は返さない) |
| POST | /v1/admin/tokens/{id}/revoke | トークン失効 (config reload を待たずに即時拒否) |
| GET | /metrics | Prometheus metrics |

### Admin エンドポイントの認証

`/v1/admin/tokens` 系は通常の Bearer トークンとは別の管理 secret を要求する:

- config.yml の `agent.admin_token_hash` に管理 secret の **SHA-256 (hex)** を設定する (生 secret は config に置かない)
  - 例: `echo -n "$SECRET" | sha256sum | cut -d' ' -f1` の値を `admin_token_hash` に設定
- リクエストは `X-LRM-Admin-Token: <生secret>` ヘッダーで認証する (Agent側で SHA-256 化して比較)
- `admin_token_hash` 未設定の場合、admin エンドポイントは無効 (404 相当) になる
- MCP Server 側の `agent.admin_token` に**同じ生 secret** を設定する (credential の失効同期・`agent_token_id` 自動解決がこれを使う)

## Quick Start

```bash
# Build (本体)
make build

# credential-issue CLI もビルド (credential発行用)
go build -o credential-issue ./cmd/gen-token

# Run (generates self-signed cert in ./data)
make run

# Health check (no auth)
curl -k https://localhost:8443/v1/health

# トークン認証のテストには credential-issue で発行した生トークンを使う
# (config.yml の hash が空のトークンは認証されない)
./credential-issue -name readonly-token -scope readonly -config config.yml
./credential-issue -name operator-token -scope operator -config config.yml
```

## Configuration

See `config.yml` for example configuration.

### Token Hash Generation

`credential-issue` CLI を使うのが標準 (下記)。手動で hash を計算する場合:

```bash
python3 -c "import hashlib; print(hashlib.sha256(b'your-raw-token').hexdigest())"
```

### Agent-side Credential Issuance (credential-issue)

MCP Server用credentialをAgent側で発行する標準CLI。CSPRNGで生トークンを生成し、
SHA-256 hashをconfig.ymlへ追記 (-apply) した上で、生トークンとConsole登録用の
curlコマンドを一度だけ表示する。

```bash
# ビルド
go build -o credential-issue ./cmd/gen-token

# 発行 (config.yml に hash を書き込み、生値と登録用curlを表示)
./credential-issue -name web01-agent -scope operator -config config.yml -apply

# go run でも可
go run ./cmd/gen-token -name web01-agent -scope operator -config config.yml -apply
```

オプション:

| フラグ | 説明 |
|--------|------|
| `-name` | credential名 (必須)。Console側のcredential nameと一致させる (一致すれば `agent_token_id` は自動解決される) |
| `-id` | config.yml内のtoken id (省略時: `credential-<name>`)。既存idと重複するとエラー |
| `-scope` | `readonly` または `operator` (省略時: `readonly`) |
| `-config` | config.yml のパス (省略時: `config.yml`) |
| `-apply` | config.ymlへ追記する (未指定ならスニペット表示のみ)。既存ファイルは `.bak` に退避 (0600) |
| `-registration-file` | Console登録APIへそのままPOSTできるJSONを **0600のファイルへ出力**する (生トークンを端末へ出さない) |
| `-server-id` | `-registration-file` と併用 (Console側のserver id)。`agent_token_id` も埋め込むためConsole側のAgent照会は不要 |
| `-raw-token-file` | 生トークンを **0600のファイルへ出力**する (端末・ログ・履歴へ出さない) |
| `-set-admin-token` | 管理secretのSHA-256を `agent.admin_token_hash` へ反映するモード |
| `-admin-token-file` | 管理secretを格納したファイル (`-` で標準入力)。**secret自体は保存も表示もしない** |
| `-replace-admin-token` | 既存と異なる `admin_token_hash` を明示的に置換する (既定は上書き拒否) |

- 生トークンはファイル出力を指定しない場合のみ標準出力に**一度だけ**表示される (config.yml には hash のみ保存)
- config watcher (5秒間隔) により、`-apply` 後はAgentへ自動反映される
- YAML更新はコメント・未知キーを保持する。初回更新時にコメント周辺の空行が再整形される場合がある
  (内容は失われない)。更新前の内容は `config.yml.bak` (0600) へ退避される

生トークンを端末へ出さずに発行〜登録する例:

```bash
# 1) 発行 (registration payload を 0600 で出力)
sudo credential-issue -name web01-agent -scope operator \
  -config /etc/lrm-mcp-agent/config.yml -apply \
  -registration-file /root/registration.json -server-id web01

# 2) Consoleへ一度だけ提出し、直後に削除
curl -X POST https://<mcp-server>/api/agent-credentials \
  -H "Content-Type: application/json" --data-binary @/root/registration.json
rm -f /root/registration.json
```

管理トークン (Consoleからの失効同期に使う `agent.admin_token_hash`) の設定:

```bash
# secret はファイル経由で渡す (引数・履歴へ残さない)
printf '%s' '<admin-secret>' > /root/.lrm-admin-secret && chmod 600 /root/.lrm-admin-secret
sudo credential-issue -set-admin-token -admin-token-file /root/.lrm-admin-secret \
  -config /etc/lrm-mcp-agent/config.yml
# 標準出力に admin_token_hash=<hex> が表示される (Console側 agent.admin_token と同じ secret を設定)
```

詳細は `doc/Operations.md` の「Agent credentialの生成・ローテーション」を参照。

## Deployment

### systemd

```bash
sudo ./scripts/setup.sh             # 導入のみ (専用ユーザー/config/systemd unit)
sudo ./scripts/setup.sh --provision # 導入 + 管理hash設定 + credential発行 + Console登録 + 起動/疎通確認
```

エージェントホストへ配布するバイナリの準備 (Goが無い環境ではDockerを使用):

```bash
make dist        # dist/linux-amd64/{lrm-mcp-agent,credential-issue} を生成 (arm64 は DIST_ARCH=arm64)
# 生成物を setup.sh と同じディレクトリ (または <dir>/dist/linux-amd64/) へコピーしてから実行する
# 例: scp dist/linux-amd64/lrm-mcp-agent dist/linux-amd64/credential-issue <host>:/opt/lrm-mcp-agent/
```

`credential-issue` が見つからない場合や、古いバイナリを使った場合は
`setup.sh --provision` が異常終了し、探索パスとビルド手順を表示する
(古いバイナリは `flag provided but not defined: -set-admin-token` で失敗するため必ず再ビルドする)。

`--provision` は対話式。非対話 (CI/自動化) では環境変数で入力を渡す:

```bash
sudo LRM_SERVER_ID=web01 \
     LRM_CREDENTIAL_NAME=web01-agent \
     LRM_CREDENTIAL_SCOPE=operator \
     LRM_AGENT_ADMIN_TOKEN_FILE=/root/.lrm-admin-secret \
     LRM_CONSOLE_URL=https://console.example.jp \
     LRM_CONSOLE_AUTH_HEADER_FILE=/root/.console-auth-header \
     LRM_REQUIRE_REGISTRATION=1 \
     ./scripts/setup.sh --provision
```

provision の制約:

- 管理secret と Console認証情報はファイル (または `-` で標準入力) 経由でのみ受け取り、引数・ログ・履歴へ残さない
- `LRM_CONSOLE_AUTH_HEADER_FILE` は1行1ヘッダで複数行指定できる
  (OIDCセッション利用時は `Cookie:` と `X-CSRF-Token:` の2行を指定)
- curl へは `-K` 設定ファイル経由で渡すため、認証情報やペイロードが `ps` に露出しない
- 一時ファイルは `trap` で終了時に削除する
- 既存と異なる `admin_token_hash` は上書きせず異常終了する (`LRM_REPLACE_ADMIN_TOKEN=1` で明示置換)
- Console登録に失敗した場合は、生トークンを含む登録用ペイロードを 0600 で保存して再送を促す
  (Agent側 config はロールバックしない。提出後は `rm -f` で削除する)
- 必須入力が非対話で欠けている場合は明示エラーで終了する (`LRM_SERVER_ID` など)
- 全オプションの一覧: `sudo ./scripts/setup.sh --help`

旧方式 (既存トークンの hash を対話的に設定): `sudo ./scripts/setup-tokens.sh`

### Docker

```bash
make docker
docker run -p 8443:8443 -v /var/lib/lrm-mcp-agent:/app/data lrm-mcp-agent:latest
```

## Security Design

- AI ≠ root (dedicated user, not root)
- Token is authentication, not authorization
- Structured API preferred over shell
- Deny by default
- Token leak assumed (defense in depth)
