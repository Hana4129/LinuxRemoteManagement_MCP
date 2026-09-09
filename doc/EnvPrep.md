# 実環境検証の事前準備（手順書）

本番環境で実施する残タスク（P0-2 / P2-12 / 3.1 / P1-6 / P2-10）の**事前準備チェックリスト**。
作業は **ローカルでは行わず本番/実機で実施** する方針（Plane 事前準備チケットに記載）。
各項目を完了したら、Plane 事前準備チケットに確認結果をコメントする。

---

## 0. 対象タスクと必要リソースの対応表

| # | 必要リソース | 対応タスク | 内容 |
|---|-------------|-----------|------|
| A | **別Linuxサーバー（Agent導入用）** | 3.1 / P1-6 / P2-12 / P0-2 | Agent を配置して実統合・失効・監査検証するサーバー |
| B | **本番MCP Server導入サーバー** | P0-2 / P1-6 / P2-10 / P2-12 / 3.1 | 管理コンソール + MCP HTTP を稼働させる Linux サーバー |
| C | **mTLS用証明書一式（実CA / 社内CA）** | P0-2 / P2-12 | Agent サーバー証明書、MCP Server クライアント証明書、CA、CRL |
| D | **ネットワーク境界情報** | P2-10 | 管理NW / 利用者NW / VPN、firewall 設定権限 |
| E | **systemd 導入環境（root 権限）** | P0-2 / 3.1 / P1-6 | Agent と MCP Server の systemd ユニット配置・起動 |

---

## A. 別Linuxサーバー（Agent導入用）

### A-1. サーバー要件
- OS: **Ubuntu 22.04 LTS / 24.04 LTS** または **Rocky Linux 9**（推奨）
- 必要な権限: root（専用ユーザー作成、systemd unit 配置、証明書配置）
- ネットワーク: MCP Server からの HTTPS(8443) 到達が可能なこと
- 時間同期: chrony / systemd-timesyncd で NTP 同期（監査ログ時刻の正確性）

### A-2. MSTeamsで提供してほしい情報（事前準備チケットのコメント欄へ）
| 項目 | 例 |
|------|-----|
| ホスト名 | `agent-prod-01` |
| IPアドレス / FQDN | `10.0.0.10` / `agent-prod-01.example.local` |
| OS・バージョン | Ubuntu 24.04 LTS |
| 到達経路 | Private NW 固定 IP（VPN 非経由を推奨） |
| SSH 可否 | 検証実施者へ sudoer 提供 or root 提供（※推奨: 専用ユーザー + sudo） |

### A-3. 検証時に投入するもの（Cline/検証者が実施）
```bash
# ビルド（ローカル or 検証端末）
cd lrm-mcp-agent && make build

# 導入（root で実行。専用ユーザー/group作成、systemd unit、ディレクトリ権限）
sudo bash scripts/setup.sh

# トークン設定（readonly / operator 各トークンの SHA-256 ハッシュを config に反映）
sudo bash scripts/setup-tokens.sh /etc/lrm-mcp-agent/config.yml

# 起動・確認
sudo systemctl enable --now lrm-mcp-agent
systemctl is-active lrm-mcp-agent
curl http://127.0.0.1:8443/v1/health
```

---

## B. 本番MCP Server導入サーバー

### B-1. サーバー要件
- OS: **Ubuntu 22.04 LTS / 24.04 LTS** または **Rocky Linux 9**（推奨）
- Python: **3.10 以上**
- 必要な権限: root（`linux-mcp` 専用ユーザー、systemd unit、証明書配置）
- 時間同期: NTP 同期

### B-2. 提供してほしい情報
| 項目 | 例 |
|------|-----|
| ホスト名 | `mcp-prod-01` |
| IPアドレス / FQDN | `10.0.0.20` / `mcp-prod-01.example.local` |
| OS・Python バージョン | Ubuntu 24.04 LTS / Python 3.12 |
| 到達経路 | 管理NW（社内管理のみ）、利用者NW（MCP HTTP 8090） |
| リバースプロキシの有無 | nginx / Apache / LB（TLS 終端位置の要確認） |

### B-3. 検証時に投入するもの
```bash
# 導入（root）
cd mcp-server
sudo bash scripts/setup.sh
# systemd unit 配置（Operations.md §1.4）
sudo install -m 644 scripts/linux-mcp-console.service /etc/systemd/system/
sudo install -m 644 scripts/linux-mcp-http.service  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linux-mcp-console.service linux-mcp-http.service
```

---

## C. mTLS用証明書一式（P0-2 / P2-12）

### C-1. 使用CAの決定
- **社内CA** を使う場合: CA 証明書 `ca.crt` を入手（社内CA管理部門に発行依頼）
- **新規CA** を作る場合（本格的には回避推奨、検証用途のみ）:
  ```bash
  openssl genrsa -out ca.key 4096
  openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=Linux MCP CA/O=<企業名>"
  # ca.key は厳重管理 (chmod 600, off-line保管)
  ```

### C-2. 発行する証明書（3種）
| 種別 | CN | SAN | 用途 |
|------|-----|-----|------|
| Agent サーバー証明書 | `agent-prod-01` | `DNS:agent-prod-01.example.local,IP:10.0.0.10` | Agent の TLS サーバー証明書 |
| MCP Server クライアント証明書 | `mcp-client` | （任意） | MCP Server が提示するクライアント証明書 |
| CA 証明書 | 上記 CN | - | 相互検証のトラストアンカー |

### C-3. 失効検証用の準備（P2-12 完了条件）
- **CRL 配布**（推奨）: 失効時に `crl.pem` を MCP Server 側 `ca_crl_file` で参照
  - CRL 発行:
    ```bash
    openssl ca -gencrl -keyfile ca.key -cert ca.crt -out crl.pem
    ```
- **OCSP** を別途構築する場合: OCSP responder のURLを確認

### C-4. 証明書の受け渡し方法
- 秘密鍵を含むため、**暗号化した zip / 社内Secret基盤** で受け渡し
- パスフレーズ付き private key は MCP Server/Agent が自動起動できないため、**解除して配置**（ファイル権限 600 で保護）

---

## D. ネットワーク境界情報（P2-10）

### D-1. 提供してほしい情報
| 項目 | 例 |
|------|-----|
| 管理NW CIDR | `10.0.10.0/24`（コンソール到達可能） |
| 利用者NW CIDR | `10.0.20.0/24`（MCP HTTP 8090 到達可能） |
| MCP Server IP | `10.0.0.20` |
| Agent 配置 IP | `10.0.0.10` |
| firewall 操作権限 | ufw / firewalld / 上位装置ACL のどれか、操作者 |
| VPN 有無 | 有（リモート利用者向け） / 無 |

### D-2. 適用例（ホスト firewall）
```bash
# MCP Server ホスト
sudo ufw allow from 10.0.10.0/24 to any port 8080 proto tcp   # console: 管理NWのみ
sudo ufw allow from 10.0.20.0/24 to any port 8090 proto tcp   # MCP HTTP: 利用者NWのみ
sudo ufw default deny incoming
# Agent ホスト
sudo ufw allow from 10.0.0.20 to any port 8443 proto tcp      # Agent: MCP Serverのみ
sudo ufw default deny incoming
```

---

## E. systemd 導入環境（root 権限）

- 対象: **MCP Server サーバー（B）と Agent サーバー（A）の両方**
- 確認事項:
  - systemd が利用可能（`systemctl --version`）
  - `linux-mcp`（MCP Server）と `lrm-mcp-agent`（Agent）の専用ユーザー作成権限
  - `/etc/systemd/system/` へ unit を配置する権限

---

## F. 最終確認（事前準備完了判定）

```
[ ] A: 別Linuxサーバー（Agent導入用）が提供された
[ ] B: 本番MCP Server導入サーバーが提供された
[ ] C: mTLS用証明書一式（CA / server / client / CRL）が発行・受け渡しされた
[ ] D: ネットワーク境界情報（管理NW/利用者NW/VPN/firewall権限）が判明した
[ ] E: systemd 導入が可能（root権限）である
```

すべて `[x]` になったら、Plane 事前準備チケットに記録し、**P0-2 → 3.1 → P1-6 → P2-10 → P2-12** の順に実環境検証を実施する。

---

## 参考

- mTLS 設定詳細: `doc/mTLS.md`
- 実環境検証手順全般: `doc/EnvVerification.md`
- 導入・運用: `doc/Operations.md`
- Agent セットアップ: `lrm-mcp-agent/README.md` / `lrm-mcp-agent/scripts/setup.sh`
- MCP Server セットアップ: `mcp-server/scripts/setup.sh`