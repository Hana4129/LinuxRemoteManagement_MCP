
# Linux Remote Management MCP — Security Design

## 1. 概要

本システムは、Claude / Codex等のAIエージェントから、リモートLinuxサーバーを安全に操作するためのMCPベースの管理基盤である。

SSHによる直接操作ではなく、**HTTPS API + API Token** を利用してLinux側のAgentを操作する。

基本構成は以下とする。

```text
┌──────────────────────┐
│  AI Client            │
│  Claude / Codex       │
└──────────┬───────────┘
           │ MCP
           ▼
┌──────────────────────┐
│  MCP Server           │
│                      │
│  - Tool validation    │
│  - Authorization      │
│  - Audit              │
└──────────┬───────────┘
           │ HTTPS
           │ Bearer Token
           ▼
┌──────────────────────┐
│  Linux Agent          │
│                      │
│  - Authentication     │
│  - Command Policy     │
│  - File Policy        │
│  - Process Control    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Linux OS              │
│                      │
│ systemd / filesystem │
│ processes / logs      │
└──────────────────────┘
```

---

# 2. 設計目標

## 必須要件

* SSHを管理プロトコルとして使用しない
* HTTPSによる通信
* API Tokenによる認証
* Linux Agentは専用ユーザーで動作
* root権限を原則として与えない
* 操作可能なコマンドを制限できる
* ファイルアクセス範囲を制限できる
* 全操作を監査ログに記録する
* 複数Linuxサーバーを管理できる
* MCP Toolから利用しやすいAPIを提供する

## セキュリティ目標

API Tokenが漏洩した場合でも、

> 「サーバー上の任意の操作が可能になる」

状態を避ける。

そのため、認証と認可を分離する。

```text
Authentication
    ↓
「誰がアクセスしているか」

Authorization
    ↓
「何を実行してよいか」
```

---

# 3. コンポーネント

## 3.1 MCP Server

AIクライアントとLinux Agentの間に配置する。

責務：

* MCP Toolの提供
* Tool引数のvalidation
* Linux AgentへのAPI request
* 操作ログ
* エラー処理
* サーバー選択
* 認可ポリシー適用

MCP Server自身はroot権限を持たない。

---

## 3.2 Linux Agent

各Linuxサーバーに1つ配置する。

責務：

* API Token認証
* コマンド実行
* ファイル操作
* systemd操作
* プロセス情報取得
* ログ取得
* 認可
* Audit Log

Agentは専用Unixユーザーで実行する。

例：

```text
User: linux-agent
Group: linux-agent
```

---

# 4. ネットワーク構成

推奨構成：

```text
Internet
    X
    │
    │ 直接公開しない
    │
Private Network
    │
    ├── MCP Server
    │
    └── Linux Agent
```

Linux AgentのAPIをインターネットへ直接公開しない。

可能であれば以下のいずれかを利用する。

* Tailscale
* WireGuard
* VPN
* Private VPC Network

理想構成：

```text
AI Client
    │
    ▼
MCP Server
    │
    │ Private Network
    ▼
Linux Agent
```

---

# 5. HTTPS

Linux Agentとの通信は必ずHTTPSとする。

```text
https://server.example.internal:8443
```

HTTPは許可しない。

TLS 1.2以上を使用する。

可能であればmTLSも利用する。

```text
MCP Server
    │
    │ Client Certificate
    ▼
Linux Agent
```

これにより、API Tokenだけでなく、

```text
MCP Server証明書
+
API Token
```

という二重の認証にできる。

---

# 6. API Token

単純な固定Bearer Tokenだけに依存しない。

## 最低構成

```http
Authorization: Bearer <TOKEN>
```

Tokenは十分長いランダム値とする。

例：

```text
64 bytes以上
CSPRNGで生成
```

TokenをGit repositoryに保存してはいけない。

---

# 7. Token管理

推奨：

```text
MCP Server
    │
    └── Secret Store
           │
           └── API Token
```

利用可能なSecret Storeの例：

* HashiCorp Vault
* AWS Secrets Manager
* GCP Secret Manager
* Azure Key Vault
* Kubernetes Secret

小規模環境では環境変数でもよい。

```bash
LINUX_AGENT_TOKEN=...
```

ただし、ログやプロセス一覧から漏洩しないよう注意する。

---

# 8. Tokenのローテーション

Tokenは固定永久キーにしない。

例：

```text
Token A
   ↓
Token B発行
   ↓
MCP ServerをToken Bへ変更
   ↓
Token A無効化
```

可能であればTokenに、

```text
token_id
created_at
expires_at
scope
server_id
```

を持たせる。

---

# 9. 認可モデル

最重要部分。

API Tokenによる認証後、さらに操作単位で認可する。

例：

```text
Token
 ├── server: production-01
 ├── scope: readonly
 └── commands:
       ├── systemctl status
       ├── journalctl
       └── ps
```

別Token：

```text
Token
 ├── server: production-01
 ├── scope: operator
 └── commands:
       ├── systemctl status
       ├── systemctl restart nginx
       └── journalctl
```

---

# 10. MCP Tool

MCP ServerからAIへ公開するToolは、可能な限り高レベルなAPIにする。

## 推奨

```text
get_system_info()

get_disk_usage()

get_processes()

get_service_status(service)

restart_service(service)

read_log(service, lines)

read_file(path)
```

## 非推奨

```text
execute_shell(command)
```

任意shell実行をMCP Toolとして公開すると、認可の境界が弱くなる。

---

# 11. Shell実行

どうしてもshell実行が必要な場合は、allowlist方式を採用する。

例えば：

```yaml
commands:
  - systemctl status nginx
  - systemctl restart nginx
  - journalctl -u nginx
  - df
  - free
  - ps
```

以下のような自由入力は避ける。

```text
bash -c "<AIが生成した文字列>"
```

特に、

```text
eval
bash -c
sh -c
sudo
curl | sh
wget | sh
```

などは原則禁止。

---

# 12. 危険コマンド

以下はデフォルトで禁止する。

```text
rm -rf
mkfs
dd
fdisk
parted
mount
umount
iptables
nft
useradd
userdel
passwd
chpasswd
chmod -R
chown -R
systemctl disable
systemctl mask
reboot
shutdown
poweroff
```

必要な場合のみ個別に許可する。

---

# 13. systemd操作

systemdはサービス単位でallowlistする。

例：

```yaml
services:
  nginx:
    allow:
      - status
      - restart

  docker:
    allow:
      - status

  ssh:
    allow:
      - status
```

以下は禁止：

```text
systemctl *
```

---

# 14. ファイルアクセス

ファイル操作もallowlistする。

例えば：

```yaml
filesystem:
  read:
    - /var/log/nginx/**
    - /etc/nginx/**
    - /etc/os-release

  write:
    - /etc/nginx/conf.d/**
```

以下は禁止：

```text
/etc/shadow
/etc/passwd
/root/**
/home/*/.ssh/**
/proc/**
/sys/**
```

パストラバーサル対策も必須。

```text
../../etc/shadow
```

のようなアクセスを拒否する。

---

# 15. sudo

Linux Agent自身にはroot権限を与えない。

原則：

```text
linux-agent
    ↓
通常ユーザー権限
```

root権限が必要な操作は、限定されたsudo ruleを使用する。

例：

```text
linux-agent ALL=(root) NOPASSWD:
/usr/bin/systemctl restart nginx
```

以下は禁止：

```text
linux-agent ALL=(ALL) NOPASSWD: ALL
```

---

# 16. API設計

## Health Check

```http
GET /v1/health
```

Response:

```json
{
  "status": "ok"
}
```

---

## System Information

```http
GET /v1/system
Authorization: Bearer <TOKEN>
```

Response:

```json
{
  "hostname": "server01",
  "os": "Ubuntu 24.04",
  "kernel": "6.x",
  "uptime": 123456
}
```

---

## Command

任意shellではなく、可能な限り構造化APIにする。

```http
POST /v1/services/nginx/restart
Authorization: Bearer <TOKEN>
```

Response:

```json
{
  "success": true,
  "service": "nginx"
}
```

---

## Service Status

```http
GET /v1/services/nginx
Authorization: Bearer <TOKEN>
```

Response:

```json
{
  "service": "nginx",
  "active": true,
  "status": "running"
}
```

---

## Logs

```http
GET /v1/services/nginx/logs?lines=100
Authorization: Bearer <TOKEN>
```

---

# 17. 任意Command API

どうしても必要な場合のみ提供する。

```http
POST /v1/commands
Authorization: Bearer <TOKEN>

{
  "command": "df",
  "arguments": ["-h"]
}
```

Agent側では、

```text
command
   ↓
Parser
   ↓
Allowlist
   ↓
Authorization
   ↓
Execute
```

とする。

単純な文字列検索によるblacklistは禁止。

悪い例：

```text
if "rm" not in command:
    execute(command)
```

良い例：

```text
command = "df"
arguments = ["-h"]

if command == "df":
    execute(["/bin/df", "-h"])
```

可能ならshellを経由せず、直接execする。

---

# 18. タイムアウト

全API操作にtimeoutを設定する。

例：

```yaml
timeouts:
  system_info: 5s
  service_status: 5s
  restart_service: 30s
  command: 30s
```

無期限のprocessを許可しない。

---

# 19. Resource Limit

Command実行時には以下を制限する。

* CPU
* Memory
* Process数
* 実行時間
* stdoutサイズ
* stderrサイズ
* ファイルサイズ

例えば：

```yaml
execution:
  timeout: 30s
  max_output_bytes: 1048576
```

---

# 20. Audit Log

すべての操作を記録する。

例：

```json
{
  "timestamp": "2026-08-28T14:00:00Z",
  "request_id": "req_123",
  "token_id": "tok_001",
  "server": "production-01",
  "operation": "restart_service",
  "target": "nginx",
  "result": "success",
  "duration_ms": 842
}
```

Tokenそのものはログに記録しない。

---

# 21. AI操作の監査

AI由来の操作であることも記録する。

```json
{
  "actor": "mcp",
  "client": "claude",
  "tool": "restart_service",
  "server": "production-01",
  "service": "nginx"
}
```

これにより、

```text
人間操作
AI操作
自動化操作
```

を区別できる。

---

# 22. Human Approval

破壊的操作については、AIが単独で実行できないようにする。

例：

```text
AI
 ↓
restart_service("nginx")
 ↓
Policy Check
 ↓
許可
 ↓
実行
```

一方、

```text
AI
 ↓
delete_file(...)
 ↓
Policy Check
 ↓
Human Approval Required
 ↓
ユーザー確認
 ↓
実行
```

とする。

---

# 23. Rate Limit

Token単位でrate limitを設定する。

例：

```yaml
rate_limit:
  requests_per_minute: 60
```

特にcommand APIは低くする。

```yaml
command:
  requests_per_minute: 10
```

---

# 24. Replay Attack対策

高いセキュリティが必要な環境では、Bearer Tokenだけでなくrequest signingを検討する。

```text
timestamp
nonce
method
path
body
```

を署名する。

```text
HMAC-SHA256
```

などを利用する。

---

# 25. MCP ServerとAgentの信頼境界

以下を明確に分離する。

```text
AI
 │
 │ untrusted input
 ▼
MCP Server
 │
 │ validated request
 ▼
Linux Agent
 │
 │ authorized operation
 ▼
OS
```

AIが生成した文字列を、そのままOS commandとして実行しない。

---

# 26. 複数サーバー

複数Linuxサーバーを管理する場合：

```text
                    ┌── Linux Agent A
                    │
MCP Server ─────────┼── Linux Agent B
                    │
                    ├── Linux Agent C
                    │
                    └── Linux Agent D
```

Tokenはサーバーごとに分離する。

```text
Token A → server-A only
Token B → server-B only
Token C → server-C only
```

productionとdevelopmentでTokenを共有しない。

---

# 27. Production / Development分離

必ず分離する。

```text
MCP Server
   │
   ├── Development Agent
   │      └── dev-token
   │
   └── Production Agent
          └── prod-token
```

Development用TokenからProductionへアクセスできないようにする。

---

# 28. 推奨セキュリティレベル

## Level 1 — 最小構成

```text
MCP
 ↓ HTTPS
Linux Agent
 ↓
API Token
```

用途：

* 個人サーバー
* 開発環境

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

用途：

* 自宅サーバー
* VPS
* 開発/検証環境

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

さらに、

* Token rotation
* Rate limit
* Human approval
* Network ACL
* Alerting
* Immutable audit log

を追加する。

---

# 29. 推奨Tech Stack

実装言語はPythonまたはGoを推奨。

例：

```text
MCP Server
    Python
    FastMCP

Linux Agent
    Go

Transport
    HTTPS

Authentication
    API Token
    + optional mTLS

Network
    Tailscale / WireGuard

Logging
    JSON structured log

Secrets
    Vault / Secret Manager
```

特にLinux Agentは、**Goで単一バイナリとして配布する構成**が扱いやすい。

```text
/usr/local/bin/linux-agent
```

としてsystemd service化できる。

---

# 30. systemd構成

```ini
[Unit]
Description=Linux Management Agent
After=network-online.target

[Service]
User=linux-agent
Group=linux-agent
ExecStart=/usr/local/bin/linux-agent
Restart=always

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

さらに必要に応じてsystemd sandboxingを追加する。

---

# 31. 最終推奨アーキテクチャ

本プロジェクトでは以下を標準構成とする。

```text
                     AI
                     │
                     │ MCP
                     ▼
             ┌────────────────┐
             │   MCP Server   │
             │                │
             │ Validation     │
             │ Authorization  │
             │ Audit          │
             └───────┬────────┘
                     │
                     │ HTTPS
                     │ mTLS
                     │ API Token
                     ▼
             ┌────────────────┐
             │  Linux Agent   │
             │                │
             │ Auth           │
             │ Policy         │
             │ Execution      │
             │ Audit          │
             └───────┬────────┘
                     │
              Dedicated User
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       systemd    filesystem   process
```

---

# 32. 設計上の原則

最重要原則は以下。

### 1. AIをrootとして扱わない

```text
AI ≠ root
```

### 2. Tokenは認証であって権限ではない

```text
Token valid
    ≠
Everything allowed
```

### 3. Shellより構造化APIを優先する

```text
restart_service("nginx")
```

を、

```text
bash -c "systemctl restart nginx"
```

より優先する。

### 4. Deny by default

明示的に許可されていない操作は拒否する。

### 5. ProductionはHuman Approvalを導入する

AIが破壊的操作を単独で実行できないようにする。

### 6. Token漏洩を想定する

Tokenが漏洩しても被害を限定できる設計にする。

---

# 33. MVP

最初の実装では、以下だけで開始する。

```text
MCP Tools

get_system_info
get_disk_usage
get_processes
get_service_status
restart_service
get_service_logs
read_file
execute_command
write_file
```

認証：

```text
HTTPS
+
Bearer Token
```

権限：

```text
Dedicated User
+
Allowlist
```

ネットワーク：

```text
Tailscale / WireGuard
```

ログ：

```text
JSON Audit Log (ローテーション対応)
```

セキュリティ：

```text
Rate Limit (トークンバケット)
Human Approval
```

この構成でまず実用化し、その後、

```text
mTLS
Token Rotation
Policy Engine
SIEM
```

を追加する。

---

# 34. セキュリティ結論

SSHを完全に否定する必要はない。

SSHは成熟しており、公開鍵認証・Unix権限・sudoとの統合という点では非常に強力である。

一方、AIエージェントによる操作では、

```text
SSH
 ↓
任意Shell
```

よりも、

```text
MCP
 ↓
Structured API
 ↓
Policy
 ↓
Linux Agent
```

の方が、**AIに与える権限を細かく制御しやすい**。

したがって本システムでは、

> **SSHの代替認証方式としてAPI Tokenを使う**

のではなく、

> **AIとLinux OSの間に認可境界を持つManagement APIを設置する**

という思想で設計する。

最終的な推奨構成は、

```text
MCP
  ↓
Private Network
  ↓
HTTPS + mTLS
  ↓
API Token
  ↓
Policy / Allowlist
  ↓
Dedicated Unix User
  ↓
Restricted sudo
  ↓
Linux
```

