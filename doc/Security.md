# セキュリティレベル別構成ガイド

本ドキュメントは、Linux Remote Management MCP のセキュリティレベル（Level 1〜3）別構成と、本実装がどのレベル要件を満たすかを定義する。

---

## Level 1 — 最小構成

```text
MCP
 ↓ HTTPS
Linux Agent
 ↓
API Token
```

**用途**: 個人サーバー、開発環境

**要件**:
- HTTPS による通信暗号化
- Bearer Token 認証

**本実装での対応**:
- ✅ HTTPS/TLS 1.2+ 強制（自己署名証明書自動生成）
- ✅ Bearer Token 認証（SHA-256 ハッシュ比較、constant-time）
- ✅ Token スコープ分離（readonly/operator）

---

## Level 2 — 推奨

```text
MCP
 ↓
Private Network
 ↓
HTTPS
 ↓
API Token
 ↓
Command Allowlist
 ↓
Dedicated Unix User
 ↓
Audit Log
```

**用途**: 自宅サーバー、VPS、開発/検証環境

**要件**:
- Level 1 のすべて
- Private Network 配置（VPN 等）
- Command Allowlist（deny by default）
- Dedicated Unix User（非 root）
- Audit Log（構造化、改ざん防止）

**本実装での対応**:
- ✅ Private Network: Tailscale / WireGuard 併用を推奨（config.yml で network 設定）
- ✅ Command Allowlist: `allowlist.commands` で完全一致のみ許可（deny by default）
- ✅ Dedicated Unix User: `scripts/setup.sh` で専用ユーザー作成、systemd sandboxing
- ✅ Audit Log: JSONL 構造化ログ（0600 パーミッション）、MCP 監査ログ（actor 記録）
- ✅ Rate Limit: クライアント IP 単位（token bucket、429 応答）
- ✅ Human Approval: 操作前に承認フロー（operator スコープの restart/execute）

---

## Level 3 — 本番

```text
AI
 ↓
MCP
 ↓
Policy Engine
 ↓
mTLS
 ↓
API Token
 ↓
Linux Agent
 ↓
Command Allowlist
 ↓
Dedicated User
 ↓
Restricted sudo
 ↓
Audit Log
 ↓
SIEM
```

**用途**: 本番環境、複数管理者、コンプライアンス要件

**要件**:
- Level 2 のすべて
- Policy Engine（認可の集中管理）
- mTLS（双方向認証）
- Restricted sudo（最小権限）
- SIEM 連携（アラート、改ざん検知）
- Token rotation
- Immutable audit log

**本実装での対応**:
- ✅ Policy Engine: `internal/policy/engine.go` で認可集中管理（readonly/operator スコープ）
- ✅ mTLS: Agent 側でクライアント証明書検証対応済み（config.yml で設定）
- ✅ Restricted sudo: systemd `NoNewPrivileges=true`、`ProtectSystem=strict`
- ✅ Audit Log: 構造化 JSONL、0600 パーミッション、ハッシュチェーンによる改ざん防止
- ✅ Audit Log Rotation: サイズベースローテーション、世代管理、gzip 圧縮対応
- ✅ SIEM 連合: Webhook によるリアルタイム転送対応（CEF/LEEF/JSON 形式対応）
- ✅ Token rotation: API によるローテーション対応（グラ期間、履歴管理）
- ✅ Immutable audit log: ハッシュチェーン実装済み、append-only マウントは運用時設定
- ✅ Rate Limit (MCP Server): トークンバケット方式、クライアントIP単位、429応答

---

## 実装チェックリスト

| 項目 | Level 1 | Level 2 | Level 3 | 実装状況 |
|------|---------|---------|---------|----------|
| HTTPS | ✅ | ✅ | ✅ | ✅ 実装済み |
| Bearer Token | ✅ | ✅ | ✅ | ✅ 実装済み |
| Private Network | - | ✅ | ✅ | ⚠️ 運用時 |
| Command Allowlist | - | ✅ | ✅ | ✅ 実装済み |
| Dedicated User | - | ✅ | ✅ | ✅ 実装済み |
| Audit Log | - | ✅ | ✅ | ✅ 実装済み |
| Audit Log Rotation | - | ✅ | ✅ | ✅ 実装済み |
| Rate Limit (Agent) | - | ✅ | ✅ | ✅ 実装済み |
| Rate Limit (MCP Server) | - | ✅ | ✅ | ✅ 実装済み |
| Human Approval | - | ✅ | ✅ | ✅ 実装済み |
| Policy Engine | - | - | ✅ | ✅ 実装済み |
| mTLS | - | - | ✅ | ✅ 実装済み |
| SIEM | - | - | ✅ | ✅ 実装済み |
| Token Rotation | - | - | ✅ | ✅ 実装済み |
| Immutable Log | - | - | ✅ | ✅ 実装済み |

---

## 運用時の推奨設定

### Level 2 推奨設定

```yaml
# config.yml (Agent)
agent:
  env: production
  rate_limit:
    enabled: true
    per_minute: 30
    burst: 5
  audit:
    enabled: true
    log_file: /var/log/linux-agent/audit.log
```

### Level 3 追加推奨

- Tailscale / WireGuard によるネットワーク分離
- Fluentd / Vector による audit.log の SIEM 転送
- 四半期ごとの Token ローテーション
- 監査ログのバックアップとハッシュ検証

### Level 3 SIEM 連携設定例

```yaml
# config.yml (Agent) - SIEM 転送設定
agent:
  audit:
    enabled: true
    log_file: /var/log/linux-agent/audit.log
    siem:
      enabled: true
      webhook_url: "https://siem.example.com/api/v1/events"
      api_key: "${SIEM_API_KEY}"  # 環境変数から読み込み推奨
      format: "json"  # "json", "cef", "leef" から選択
```

### Immutable Audit Log 設定例

```bash
# append-only マウントの設定 (Linux)
# /etc/fstab に以下を追加
/var/log/linux-agent /var/log/linux-agent ext4 defaults,append-only 0 2

# または chattr で個別ファイルに設定
sudo chattr +a /var/log/linux-agent/audit.log
```

### 監査ログ検証コマンド

```bash
# 監査ログの完全性を検証
lrm-mcp-agent -verify-audit /var/log/linux-agent/audit.log
```

### Token Rotation API

```bash
# トークンローテーション（グラ期間7日）
curl -X POST http://localhost:8080/api/tokens/{token_id}/rotate \
  -H "Content-Type: application/json" \
  -d '{"grace_period_days": 7, "expires_in_days": 90}'

# ローテーション履歴取得
curl http://localhost:8080/api/tokens/{token_id}/rotations

# グラ期間経過トークン一括無効化
curl -X POST http://localhost:8080/api/tokens/cleanup-grace-periods
```

### Fluentd/Vector 設定例

Fluentd または Vector を使用して audit.log を SIEM に転送する設定例です。

#### Vector 設定 (`vector.toml`)

```toml
# LRM MCP Agent の audit.log を読み取り
[sources.audit_log]
type = "file"
include = ["/var/log/linux-agent/audit.log"]
read_from = "end"

# JSON パースとエンリッチメント
[transforms.parse_audit]
type = "remap"
inputs = ["audit_log"]
source = '''
. = parse!(.message)
.timestamp = parse_timestamp!(.timestamp, format: "%+")
.severity = if .result == "denied" { "high" } else { "low" } else { "medium" }
'''

# SIEM へ転送 (HTTP シンク)
[sinks.siem_http]
type = "http"
inputs = ["parse_audit"]
uri = "https://siem.example.com/api/v1/events"
encoding.codec = "json"
auth.strategy = "bearer"
auth.token = "${SIEM_API_KEY}"

# ローカルバックアップ
[sinks.backup]
type = "file"
inputs = ["parse_audit"]
path = "/var/log/linux-agent/audit-backup-%Y-%m-%d.log"
encoding.codec = "json"
```

#### Fluentd 設定 (`fluent.conf`)

```xml
<source>
  @type tail
  path /var/log/linux-agent/audit.log
  pos_file /var/log/fluentd/audit.log.pos
  tag lrm.audit
  <parse>
    @type json
    time_key timestamp
    time_format %Y-%m-%dT%H:%M:%S%z
  </parse>
</source>

<filter lrm.audit>
  @type record_transformer
  <record>
    severity ${record["result"] == "denied" ? "high" : "low"}
    source "lrm-mcp-agent"
  </record>
</filter>

<match lrm.audit>
  @type http
  endpoint https://siem.example.com/api/v1/events
  content_type application/json
  <auth>
    method bearer
    token "#{ENV['SIEM_API_KEY']}"
  </auth>
  <buffer>
    @type file
    path /var/log/fluentd/buffer/audit
    flush_interval 10s
  </buffer>
</match>
```

### アラートルール設定例

SIEM で設定すべきアラートルールの例です。

#### 認証失敗の検知

```yaml
# Elastic Security / Wazuh ルール例
name: "LRM MCP Agent - Multiple Authentication Failures"
description: "5分以上で5回以上の認証失敗を検知"
severity: high
query: |
  event.module: lrm-mcp-agent AND 
  event.action: "auth" AND 
  event.outcome: "failure"
threshold:
  count: 5
  timeframe: 5m
action:
  - type: email
    to: security@example.com
  - type: webhook
    url: https://hooks.slack.com/services/xxx
```

#### 不審な操作の検知

```yaml
name: "LRM MCP Agent - Suspicious Operations"
description: "denied 結果の操作が急増した場合に検知"
severity: medium
query: |
  event.module: lrm-mcp-agent AND 
  event.result: "denied"
threshold:
  count: 10
  timeframe: 10m
```

#### 改ざん検知

```yaml
name: "LRM MCP Agent - Audit Log Tampering"
description: "監査ログの改ざんを検知"
severity: critical
query: |
  event.module: lrm-mcp-agent AND 
  event.action: "tamper_detected"
```

### 改ざん検証の定期実行

cron または systemd timer を使用して定期的に監査ログの完全性を検証します。

```bash
# crontab 例 (毎日午前2時に実行)
0 2 * * * /usr/local/bin/lrm-mcp-agent -verify-audit /var/log/linux-agent/audit.log || echo "Audit log verification failed" | mail -s "LRM Alert" security@example.com
```
