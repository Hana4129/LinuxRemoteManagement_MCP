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

---

## 4. バックアップと復旧

### 4.1 バックアップ対象

| ファイル | 説明 | 頻度 |
|----------|------|------|
| `mcp-server/data/tokens.db` | トークンデータベース | 毎日 |
| `mcp-server/data/mcp_audit.log` | MCP 監査ログ | ローテーション自動 |
| `lrm-mcp-agent/config.yml` | Agent 設定 | 変更時 |
| `lrm-mcp-agent/certs/` | TLS 証明書 | 更新時 |

### 4.2 バックアップ手順

```bash
# トークンデータベースバックアップ
sqlite3 mcp-server/data/tokens.db ".backup tokens_backup_$(date +%Y%m%d).db"

# 監査ログはローテーション自動 (gzip圧縮)
# config.yml はGit管理推奨
```

### 4.3 復旧手順

```bash
# トークンデータベース復旧
cp tokens_backup_20260101.db mcp-server/data/tokens.db

# MCP Server 再起動
systemctl restart linux-mcp-server
```

---

## 5. セキュリティ運用

### 5.1 定期タスク

| タスク | 頻度 | コマンド |
|--------|------|----------|
| トークンローテーション | 四半期 | `POST /api/tokens/{id}/rotate` |
| 失効トークン清理 | 毎日 | `POST /api/tokens/cleanup-grace-periods` |
| 監査ログ検証 | 毎日 | `lrm-mcp-agent -verify-audit` |
| 証明書期限確認 | 每月 | `openssl x509 -in cert.pem -noout -dates` |

### 5.2 レート制限設定

```yaml
# config.yml (MCP Server)
console:
  rate_limit_per_minute: 60    # 1クライアントあたりのリクエスト数
  rate_limit_burst: 10         # バースト許容量
  audit_max_size_mb: 10        # 監査ログ最大サイズ
  audit_max_backups: 5         # 監査ログ世代数
  audit_compress: true         # gzip圧縮
```

### 5.3 監査ログローテーション

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

---

## 6. 監視

### 6.1 ヘルスチェック

```bash
# MCP Server
curl http://localhost:8080/api/meta

# Agent
curl -k https://agent:8443/v1/health
```

### 6.2 メトリクス (Agent)

```bash
# Prometheus 形式メトリクス
curl -k https://agent:8443/metrics
```

### 6.3 ノード状況確認

```bash
# 全ノード状況
curl http://localhost:8080/api/nodes

# 特定ノード詳細
curl http://localhost:8080/api/nodes/dev-web-01
```

---

## 7. トラブルシューティング

### 7.1 よくある問題

**Q: トークンを紛失した場合**
A: 管理コンソールから新しいトークンを発行し、古いトークンを失効させてください。

**Q: 監査ログが大きすぎる場合**
A: `audit_max_size_mb` を小さくするか、`audit_max_backups` を減らしてください。

**Q: レート制限に引っかかる場合**
A: `rate_limit_per_minute` と `rate_limit_burst` を増やすか、クライアント側でリクエスト頻度を下げてください。

### 7.2 サポート

- GitHub Issues: https://github.com/Hana4219/Linux_Remote_Management_MCP/issues
