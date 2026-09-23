# 運用マニュアル

## 1. セットアップ手順

### 1.1 前提条件

- Python 3.10+ (MCP Server)
- Go 1.21+ (Linux Agent)
- Linux サーバー (Ubuntu 20.04+ 推奨)

### 1.2 MCP Server セットアップ

```bash
# リポジトリクローン
git clone https://github.com/Hana4219/Linux_Remote_Management_MCP.git
cd Linux_Remote_Management_MCP/mcp-server

# 依存関係インストール
pip install -r requirements.txt

# 設定ファイル編集
cp config.yml.example config.yml
# config.yml を編集して管理対象サーバーを登録

# 起動
python -m app
```

管理コンソールとMCP HTTPは別プロセスで起動する。

```bash
# MCP streamable HTTP (config.yml の mcp.host / mcp.port)
python -m app.mcp_http_entry
```

stdioを利用する場合は、利用者ごとに発行したMCP tokenを環境変数へ設定する。

```bash
export LINUX_MCP_TOKEN="<issued-token>"
python -m app.mcp_entry
```

### 1.4 systemdでの分離起動

本番Linuxでは、管理コンソールとMCP HTTPを別unitとして起動する。

```bash
sudo useradd --system --home /opt/linux-remote-management-mcp --shell /usr/sbin/nologin linux-mcp
sudo install -d -o linux-mcp -g linux-mcp -m 700 /opt/linux-remote-management-mcp/mcp-server/data
sudo install -d -m 700 /etc/linux-mcp-server
sudo install -m 600 mcp-server/scripts/env.example /etc/linux-mcp-server/env
# /etc/linux-mcp-server/env の秘密を本番値へ変更
sudo install -m 644 mcp-server/scripts/linux-mcp-console.service /etc/systemd/system/
sudo install -m 644 mcp-server/scripts/linux-mcp-http.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linux-mcp-console.service linux-mcp-http.service
```

状態確認:

```bash
systemctl status linux-mcp-console.service
systemctl status linux-mcp-http.service
journalctl -u linux-mcp-console.service -f
journalctl -u linux-mcp-http.service -f
```

`env.example` はテンプレートであり、実際の秘密をリポジトリへ保存しない。管理コンソールとMCP HTTPは異なるfirewall ruleまたはreverse proxy locationで公開する。

### 1.3 Linux Agent セットアップ

```bash
# ビルド
cd lrm-mcp-agent
make build

# 専用ユーザー作成
sudo useradd -r -s /bin/false linux-agent

# 証明書生成 (自己署名)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# 設定ファイル編集
cp config.yml.example config.yml
# config.yml を編集してトークンとallowlistを設定

# systemd で起動
sudo cp scripts/linux-agent.service /etc/systemd/system/
sudo systemctl enable linux-agent
sudo systemctl start linux-agent
```

---

## 2. トークン管理

### 2.1 トークン発行

```bash
# 読み取り専用トークン
curl -X POST http://localhost:8080/api/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "readonly-token", "scope": "readonly", "server_ids": ["*"]}'

# 操作トークン
curl -X POST http://localhost:8080/api/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "operator-token", "scope": "operator", "server_ids": ["dev-web-01"]}'
```

### 2.2 トークンローテーション

```bash
# ローテーション実行 (グラ期間7日)
curl -X POST http://localhost:8080/api/tokens/{token_id}/rotate \
  -H "Content-Type: application/json" \
  -d '{"grace_period_days": 7, "expires_in_days": 90}'

# ローテーション履歴取得
curl http://localhost:8080/api/tokens/{token_id}/rotations

# グラ期間経過トークン一括無効化
curl -X POST http://localhost:8080/api/tokens/cleanup-grace-periods
```

### 2.3 トークン失効

```bash
# 即座に失効
curl -X POST http://localhost:8080/api/tokens/{token_id}/revoke

# 削除
curl -X DELETE http://localhost:8080/api/tokens/{token_id}
```

### 2.4 Agent credentialの生成・ローテーション

Agent credential (MCP Server が各Agentへ認証するためのBearer token) は、
**Agent側のCLIツール (`credential-issue`) で発行し、生値をConsoleへ一度だけ提出する**方式を標準とする。
発行主体がAgent側にあるため、生値がConsoleのレスポンスやログを経由せず、
Agentのconfig.ymlへ直接反映される。

#### 発行 (標準フロー: Agent側発行)

```bash
# Agentホスト上で実行 (-apply でconfig.ymlへ自動追記 / .bak退避)
./credential-issue -name web01-agent -scope operator -config /etc/lrm-mcp-agent/config.yml -apply
```

- CSPRNGで生トークンを生成し、SHA-256 hashをconfig.ymlの `tokens:` へ追記する
  (token idはデフォルトで `credential-<name>`)
- config watcherが有効なら5秒以内にAgentへ自動反映される
- 標準出力に **生トークンとConsole登録用のcurlコマンドが一度だけ表示される**

表示されたcurlコマンドを実行してConsoleへ登録する (`server_id` はConsole側の
サーバーIDを指定):

```bash
curl -X POST https://<mcp-server>/api/agent-credentials \
  -H "Content-Type: application/json" \
  -d '{"server_id": "web01", "name": "web01-agent", "token": "lra_..."}'
```

- `agent_token_id` は省略可能: ConsoleがAgentに `GET /v1/admin/tokens/` で問い合わせ、
  **name一致するtokenのidを自動解決する** (Agent側発行のnameとConsole登録のnameを
  一致させれば指定不要)
- 生値はConsoleの `data_dir/tokens.db` へ AES-256-GCM で暗号化して保存される
  (MCP Server がAgentへのアウトバウンド認証のBearerとして使用するため生値が必要)
- 生値はレスポンス・ログ・一覧APIに再表示されない

`-apply` を付けずに実行した場合は config.yml は更新されず、
手動追記用のスニペットが表示される。

`agent_token_id` 自動解決の注意点:

- Consoleの `agent.admin_token` 設定が必須 (未設定時は400で案内される)
- Agent側config.yml内でnameが一意でないと解決できず400で候補idが返る
- Agentが停止中など一覧取得に失敗した場合も400になるため、
  その場合のみ `agent_token_id` を明示指定する (fail-closed)

(代替フロー) Console側で生成する `POST /api/agent-credentials/generate` も
引き続き利用可能。生成した生値をAgentのconfig.ymlへ手動配布する。

#### 環境変数からの参照登録 (Secret Manager連携)

トークンの生値を管理APIリクエストへ直接載せず、環境変数名で参照して登録できる
(`env:環境変数名` 形式)。CI/CDパイプラインで Vault Agent 等から環境変数へ
シークレットを注入している環境で、生値をAPIのペイロード・ログへ露出させずに
credential を登録できる。

```bash
# 例: LRM_AGENT_TOKEN_WEB01 環境変数に生トークンが設定済みの場合
# (agent_token_id省略時はAgentへ問い合わせてname一致で自動解決)
curl -X POST http://localhost:8080/api/agent-credentials \
  -H "Content-Type: application/json" \
  -d '{"server_id": "web01", "name": "web01-agent", "token": "env:LRM_AGENT_TOKEN_WEB01"}'
```

- 環境変数が未設定・空の場合は `400` で拒否される
- 解決後の値は `data_dir/tokens.db` の `agent_credentials.token_raw` に AES-256-GCM で暗号化して保存される (鍵は環境変数 `LRM_TOKEN_ENCRYPTION_KEY` または `data_dir/token_encryption.key`)
- レスポンス・ログ・一覧APIには生値は出力されない
- 直接トークン値を指定した登録も引き続き利用可能

#### ローテーション

```bash
# ローテーション実行 (グラ期間7日 / 生tokenは一度だけ返る)
curl -X POST http://localhost:8080/api/agent-credentials/{credential_id}/rotate \
  -H "Content-Type: application/json" \
  -d '{"grace_period_days": 7}'
```

1. レスポンスの `token` (生値) をAgent側 `config.yml` へ配布し、Agentをreloadする
2. Agent側の接続確認 (ノード一覧の表示やhealthチェック) を行う
3. グラ期間 (旧credentialは `enabled=1` だが `grace_ends_at` まで) をもって
   旧credentialへのロールバックが可能
4. グラ期間経過後は旧credentialは自動的に使用不可 (`active=false`) となる

#### ローテーション履歴と完全失効

```bash
# ローテーション履歴取得
curl http://localhost:8080/api/agent-credentials/{credential_id}/rotations

# グラ期間経過した旧credentialを一括無効化 (完全失効)
# systemd timer / cron で日次実行を推奨
curl -X POST http://localhost:8080/api/agent-credentials/cleanup-grace-periods
```

| 状態 | enabled | active | 説明 |
|------|---------|--------|------|
| 新credential | 1 | true | 現在使用中 |
| 旧credential (グラ期間中) | 1 | true | ロールバック用に残存 |
| 旧credential (グラ期間経過) | 1 | false | 使用不可、cleanup待ち |
| 完全失効後 | 0 | false | cleanup実行後 |

---

## 3. 障害対応

### 3.1 MCP Server が起動しない

| 症状 | 原因 | 対処 |
|------|------|------|
| `ModuleNotFoundError` | 依存関係未インストール | `pip install -r requirements.txt` |
| `config.yml が見つかりません` | 設定ファイル不在 | `mcp-server/config.yml` を配置 |
| `ポートが使用中` | 既にプロセスが起動 | `lsof -i :8080` で確認後、停止 |

### 3.2 Agent に接続できない

| 症状 | 原因 | 対処 |
|------|------|------|
| `接続失敗 (not_responding)` | Agent 未起動 | `systemctl status linux-agent` で確認 |
| `接続失敗 (unreachable)` | ネットワーク障害 | `curl -k https://agent:8443/v1/health` で確認 |
| `認証エラー (401)` | トークン無効 | トークン再発行 |
| `HTTP 403` | 権限不足 | トークンスコープを確認 |
| `HTTP 429` | レート制限 | 待機後再試 |

### 3.3 ログの確認

```bash
# MCP Server ログ
journalctl -u linux-mcp-server -f

# Agent ログ
journalctl -u linux-agent -f

# 監査ログ
tail -f mcp-server/data/mcp_audit.log
tail -f /var/log/linux-agent/audit.log
```

### 3.5 SIEM への監査ログ転送

`mcp_audit` が有効な場合、各監査ログエントリを外部 SIEM の webhook へ非同期で転送できる。

```yaml
# config.yml
console:
  mcp_audit: true
  siem_webhook: https://siem.example/ingest
  siem_api_key: <Bearer token>  # 省略可
```

- 転送は別スレッドで行われ、webhook への到達不良が監査ログファイルの書き込みを阻害しない
- `siem_api_key` が設定されている場合、`Authorization: Bearer <key>` ヘッダーが付与される
- 転送先が 4xx/5xx でもリトライは行わない (ログへの影響を避けるため)
- 機密値 (`token`, `Authorization` 等) はマスクされた状態で送信される

---

## 4. Agent失効同期のpending解消

Agent停止中にAgent credentialを失効した場合、MCP Server側は即座にローカル失効を完了させ (fail-closed)、同期状態が `pending` として記録される。Agent復旧後に以下の手順でAgentへ失効を再送する。

```bash
# pendingのcredentialを一括再送 (Agent復旧後に実行)
curl -u admin:password -X POST https://console.example/api/agent-credentials/resync-pending

# 個別に再送
curl -u admin:password -X POST https://console.example/api/agent-credentials/{credential_id}/resync
```

| 項目 | 動作 |
|------|------|
| 同期成功 (HTTP 200/202/204) | `agent_sync_state` が `synced` に更新される |
| 同期対象なし (HTTP 404) | 「既に失効済み/未登録」として `synced` に更新される (冪等) |
| 到達不能・HTTP 4xx/5xx | `pending` のまま維持される (fail-closed継続) |
| 失効していないcredential | 409で拒否される |

- 再送は冪等であり、複数回実行しても安全
- 定期実行する場合はsystemd timerまたはcronで `resync-pending` を呼び出す
- pending一覧は `GET /api/agent-credentials` の `agent_sync_state` で確認できる

---

## 5. バックアップと復旧

### 5.1 バックアップ対象

| ファイル | 説明 | 頻度 |
|----------|------|------|
| `mcp-server/data/tokens.db` | トークンデータベース | 毎日 |
| `mcp-server/data/mcp_audit.log` | MCP 監査ログ | ローテーション自動 |
| `lrm-mcp-agent/config.yml` | Agent 設定 | 変更時 |
| `lrm-mcp-agent/certs/` | TLS 証明書 | 更新時 |

### 5.2 バックアップ手順

```bash
# トークンデータベースバックアップ
sqlite3 mcp-server/data/tokens.db ".backup tokens_backup_$(date +%Y%m%d).db"

# 監査ログはローテーション自動 (gzip圧縮)
# config.yml はGit管理推奨
```

### 5.3 復旧手順

```bash
# トークンデータベース復旧
cp tokens_backup_20260101.db mcp-server/data/tokens.db

# MCP Server 再起動
systemctl restart linux-mcp-server
```

---

## 6. セキュリティ運用

### 6.1 定期タスク

| タスク | 頻度 | コマンド |
|--------|------|----------|
| トークンローテーション | 四半期 | `POST /api/tokens/{id}/rotate` |
| 失効トークン清理 | 毎日 | `POST /api/tokens/cleanup-grace-periods` |
| Agentの監査ログ検証 | 毎日 | `lrm-mcp-agent -verify-audit` |
| MCP Serverの監査ログ検証 | 毎日 | `python -m app.verify_audit_log mcp-server/data/mcp_audit.log` |
| 証明書期限確認 | 每月 | `openssl x509 -in cert.pem -noout -dates` |

### 6.2 レート制限設定

```yaml
# config.yml (MCP Server)
console:
  rate_limit_per_minute: 60    # 基本: 1クライアント (IP もしくは IP+トークン) あたりのリクエスト数
  rate_limit_burst: 10         # 基本: バースト許容量
  # --- レート制限の高度化 (0 の場合は基本値へフォールバック) ---
  rate_limit_write_per_minute: 20   # 操作系 (POST/PUT/PATCH/DELETE) の分離バケット
  rate_limit_write_burst: 5          # 操作系のバースト許容量
  rate_limit_token_per_minute: 120   # Bearer トークン単位の分離バケット
  rate_limit_token_burst: 30         # トークン単位のバースト許容量
  audit_max_size_mb: 10        # 監査ログ最大サイズ
  audit_max_backups: 5         # 監査ログ世代数
  audit_compress: true         # gzip圧縮
```

レート制限は **IP+トークン複合キー** で計上されるため、同一 NAT 配下の複数クライアントを
トークン単位で分離できる (Bearer トークンは SHA-256 ハッシュに変換してキー化され、
生値はメモリ上にも残らない)。操作系は読み取りと独立したバケットで制限される。
超過すると `429 Too Many Requests` (Retry-After: 60) が返る。

### 6.3 監査ログローテーション

```yaml
# config.yml (Agent)
agent:
  audit:
    enabled: true
    log_file: /var/log/linux-agent/audit.log
    rotation:
      max_size_mb: 10      # 10MBでローテーション
      max_backups: 5       # 5世代保持
      compress: true       # gzip圧縮
```

### 6.4 MCP Server 監査ログのハッシュチェーン検証

MCP Server の監査ログ (`mcp-server/data/mcp_audit.log`) はエントリごとに
SHA-256 ハッシュチェーン (`prev_hash` / `hash`) を持ち、改ざんを検知できる。

```bash
# 検証 (正常: OK / 異常: FAIL + 問題行、終了コード 1)
cd mcp-server
python -m app.verify_audit_log data/mcp_audit.log

# 複数ファイルも指定可能
python -m app.verify_audit_log data/mcp_audit.log data/mcp_audit.log.1.gz
```

- 旧形式 (hash なし) エントリはスキップされ、ローテーション前ファイルへの
  参照 (先頭エントリの非空 `prev_hash`) は許容される
- 検証結果は監査ログ検証タスクとして日次で実行し、改ざんが疑われる場合は
  該当ファイルとキー整合性を調査する

append-only 保持の推奨:

```bash
# 監査ログディレクトリを読み取り専用マウント、または chattr +a で追記専用化
sudo chattr +a /opt/linux-remote-management-mcp/mcp-server/data/mcp_audit.log
```

---

### 6.5 設定ファイルの機密情報保護 (Secret References)

`config.yml` にシークレット (password, API Key, Token, 証明書パス等) を
平文で保存しない。**環境変数参照** (`${ENV_VAR}`) の形式を使用する。

```yaml
console:
  # 実際の値は環境変数で提供。config.yml には参照を保持。
  username: ${LINUX_MCP_CONSOLE_USER}
  password: ${LINUX_MCP_CONSOLE_PASS}
  siem_api_key: ${MCP_SIEM_API_KEY:-}

agent:
  admin_token: ${LINUX_MCP_AGENT_ADMIN_TOKEN}
  client_cert: ${MCP_AGENT_CLIENT_CERT:-}
  client_key: ${MCP_AGENT_CLIENT_KEY:-}
```

#### 参照形式

| 形式 | 説明 |
|------|------|
| `${VAR_NAME}` | 環境変数 `VAR_NAME` の値に展開。未設定の場合 **エラー** (fail-closed) |
| `${VAR_NAME:-default}` | 未設定時に `default` を使用 |
| `${VAR_NAME:-}` | 未設定時に空文字列 |

#### 運用ベストプラクティス

1. **シークレットは環境変数・Secret Store (Vault 等) から注入**
   - systemd の `EnvironmentFile` に `/etc/linux-mcp-server/env` (chmod 600) を指定
   - `mcp-server/scripts/env.example` をテンプレートとして使用
   - 本番では Vault / KMS から動的に環境変数を注入することを推奨

2. **config.yml は Git 管理可能**
   - シークレットは含まれないため、リポジトリで安全に管理できる
   - `data/tokens.db` と `env` ファイルは `.gitignore` 対象

3. **save() 時の安全性**
   - `save()` は元の `${ENV_VAR}` 参照をそのまま保持する
   - 平文のシークレットが config.yml へ書き出されることはない

4. **トークン暗号化**
   - MCP トークンは AES-256-GCM で暗号化して DB に保存 (§3.1)
   - 暗号化鍵は `LRM_TOKEN_ENCRYPTION_KEY` 環境変数 (Vault から注入推奨)

### 6.6 生トークン暗号化 (AES-256-GCM)

MCPトークンとAgent credentialの生値をSQLiteに平文で保存しない。
`app/secretbox.py` が AES-256-GCM による保存時暗号化を提供する。

```yaml
# 暗号化キー解決順:
# 1. 環境変数 LRM_TOKEN_ENCRYPTION_KEY (32バイトのhex/base64)
# 2. キーファイル <data_dir>/token_encryption.key (自動生成、0600)
```

- 保存形式: `enc.v1.<nonce base64url>.<ciphertext base64url>`
- SHA-256ハッシュ (`token_hash`) は暗号化の影響を受けない (照合可能)
- トークン発行時は生トークンを1回のみ返し、2回目は取得不可

### 6.7 レート制限高度化 (トークンレベル制限)

MCP Serverのレート制限は **IP+トークン複合キー** で計上される。

```yaml
# config.yml
console:
  rate_limit_per_minute: 60      # 基本値 (トークン別設定がない場合)
  rate_limit_burst: 10
  rate_limit_write_per_minute: 30  # 操作系 (デフォルト: 基本値の半値)
  rate_limit_token_per_minute: 0   # トークン別 (0=基本値へフォールバック)
```

- BearerトークンはSHA-256ハッシュに変換してキー化 (生値はメモリ上に残らない)
- 操作系 (`execute_command`, `restart_service` 等) は読み取りと独立したバケットで制限
- 超過時: `429 Too Many Requests` (Retry-After: 60)

---

## 7. 監視

### 7.1 ヘルスチェック

```bash
# MCP Server
curl http://localhost:8080/api/meta

# Agent
curl -k https://agent:8443/v1/health
```

### 7.2 メトリクス (Agent)

```bash
# Prometheus 形式メトリクス
curl -k https://agent:8443/metrics
```

### 7.3 ノード状況確認

```bash
# 全ノード状況
curl http://localhost:8080/api/nodes

# 特定ノード詳細
curl http://localhost:8080/api/nodes/dev-web-01
```

---

## 8. トラブルシューティング

### 8.1 よくある問題

**Q: トークンを紛失した場合**
A: 管理コンソールから新しいトークンを発行し、古いトークンを失効させてください。

**Q: 監査ログが大きすぎる場合**
A: `audit_max_size_mb` を小さくするか、`audit_max_backups` を減らしてください。

**Q: レート制限に引っかかる場合**
A: `rate_limit_per_minute` と `rate_limit_burst` を増やすか、クライアント側でリクエスト頻度を下げてください。

### 8.2 サポート

- GitHub Issues: https://github.com/Hana4219/Linux_Remote_Management_MCP/issues
