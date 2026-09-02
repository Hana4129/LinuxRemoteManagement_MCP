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
- ✅ Audit Log: 構造化 JSONL、0600 パーミッション
- ⚠️ SIEM 連合: 未実装（運用時は Fluentd/Vector 等で `audit.log` を転送）
- ⚠️ Token rotation: 未実装（運用時に `cmd/gen-token` で定期ローテーション）
- ⚠️ Immutable audit log: 未実装（運用時に append-only マウント or SIEM 転送）

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
| Rate Limit | - | ✅ | ✅ | ✅ 実装済み |
| Human Approval | - | ✅ | ✅ | ✅ 実装済み |
| Policy Engine | - | - | ✅ | ✅ 実装済み |
| mTLS | - | - | ✅ | ✅ 実装済み |
| SIEM | - | - | ✅ | ⚠️ 運用時 |
| Token Rotation | - | - | ✅ | ⚠️ 運用時 |
| Immutable Log | - | - | ✅ | ⚠️ 運用時 |

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
