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
- ネットワーク: MCP Server からの HTTPS(9443) 到達が可能なこと
  - ※ 既定は 8443 だが、本件環境では docker-proxy が 8443 を占有中のため **9443** を使用する
    (Agent `agent.listen: ":9443"` + MCP Server `servers[].url: https://<host>:9443` + firewall の3点連動)
- 時間同期: chrony / systemd-timesyncd で NTP 同期（監査ログ時刻の正確性）

#### A-1. 確認手順（要件ごとに合否判定・詳細は A-4）

```bash
# [A] 要件1: OS が推奨範囲内か
lsb_release -a 2>/dev/null || cat /etc/os-release
# 期待: Ubuntu 22.04/24.04 または Rocky 9。合否: ○=範囲内 / ×=範囲外(要相談)

# [A] 要件2: root または sudo 可能か
id -u   # 期待: 0 (root 直実行)
sudo -n true && echo "sudo-ok" || echo "sudo-ng (要パスワード or 未付与)"
# 期待: root 直実行 or sudo-ok。合否: ○=いずれか / ×=どちらも不可

# [A] 要件3: 自ホストで 9443/tcp が listen 可能か (Agent導入前は「空き」確認)
# ※ 既定8443は本件環境でdocker-proxyが占有中のため 9443 を使用する
ss -tlnp | grep 9443 || echo "9443-free (導入前は正常)"
ss -tlnp | grep 8443 || echo "8443-note (docker-proxy占有を確認済み)"
# 期待: 導入前=9443空き、導入後=9443 LISTEN。合否: ○=9443に競合なし

# [A] 要件4: NTP 同期済みか (監査ログ時刻の正確性)
timedatectl show | grep NTPSynchronized
chronyc tracking 2>/dev/null | grep -E "Leap status|System time" || systemctl is-active chrony* systemd-timesyncd* --no-pager
# 期待: NTPSynchronized=yes / Leap status: Normal。合否: ○=同期済み / ×=未同期(要NTP設定)
```

> 判定が1つでも × の場合は A-4 / F-2 に記録し、先に是正してから導入 (A-3) へ進む。

### A-2. MSTeamsで提供してほしい情報（事前準備チケットのコメント欄へ）
| 項目 | 例 |
|------|-----|
| ホスト名 | `agent-prod-01` |
| IPアドレス / FQDN | `10.0.0.10` / `agent-prod-01.example.local` |
| OS・バージョン | Ubuntu 24.04 LTS |
| 到達経路 | Private NW 固定 IP（VPN 非経由を推奨） |
| SSH 可否 | 検証実施者へ sudoer 提供 or root 提供（※推奨: 専用ユーザー + sudo） |

#### A-2. 確認手順（提供情報の受領・突合チェック）

```bash
# [V] 1. 受領チェック (MSTeams/チケットの申告を転記・欠落確認)
# 必須5点: ホスト名 / IP-FQDN / OS / 到達経路 / SSH可否
# 期待: 5点そろっていること。欠落があれば提供者へ差し戻し (×=導入作業に入らない)

# [V] 2. SSH 接続の実測 (検証実施者の端末から)
ssh <user>@<agent-ip-or-fqdn> "hostname -f; id -u; sudo -n true && echo sudo-ok"
# 期待: ホスト名が申告と一致、uid=0 or sudo-ok。合否: ○=一致+権限あり / ×=不一致or権限なし

# [V] 3. OS 申告との突合 (SSH先で)
ssh <user>@<agent-ip-or-fqdn> "lsb_release -a 2>/dev/null || cat /etc/os-release"
# 期待: 申告OSと一致し、A-1 要件範囲内であること

# [V] 4. 到達経路の実測 (MCP Serverホストから。VPN/Private NW の確認)
# ※ Agentポートは 9443 (既定8443はdocker-proxy占有のため変更)
# [M] で実行:
nc -zv <agent-ip-or-fqdn> 9443 || echo "not-yet (Agent導入前は不通で正常)"
ping -c 3 <agent-ip-or-fqdn>
# 期待: 導入前=ping疎通のみ (9443不通は正常)、導入後=9443疎通。申告経路(VPN/Private)と矛盾がないこと
```

Plane貼付テンプレ (A-2 受領確認):
```
[A-2] 受領5点: ホスト名=<○/×> IP-FQDN=<○/×> OS=<○/×> 到達経路=<○/×> SSH=<○/×>
[A-2] SSH実測: hostname=<一致/不一致> 権限=<uid/sudo-ok/ng>
[A-2] OS突合: 申告=<...> 実測=<...> 要件範囲=<○/×>
[A-2] 経路実測: ping=<ok/ng> 9443=<導入前不通で正常/導入後ok> 経路矛盾=<有/無>
```

### A-3. 検証時に投入するもの（Cline/検証者が実施）

> ※ Agentポートは **9443** (既定8443はdocker-proxy占有のため変更)。以下3点を連動させる:
> ① Agent `agent.listen: ":9443"` ② MCP Server `servers[].url: https://<host>:9443` ③ firewall 9443許可
```bash
# ビルド（ローカル or 検証端末）
cd lrm-mcp-agent && make build

# Agent listen変更 (config.yml の agent.listen を ":9443" に)
# /etc/lrm-mcp-agent/config.yml (導入後に編集):
#   agent:
#     listen: ":9443"

# 導入（root で実行。専用ユーザー/group作成、systemd unit、ディレクトリ権限）
sudo bash scripts/setup.sh

# トークン設定（readonly / operator 各トークンの SHA-256 ハッシュを config に反映）
sudo bash scripts/setup-tokens.sh /etc/lrm-mcp-agent/config.yml

# 起動・確認 (9443)
sudo systemctl enable --now lrm-mcp-agent
systemctl is-active lrm-mcp-agent
ss -tlnp | grep 9443
curl -sk https://127.0.0.1:9443/v1/health; echo
# 期待: 200応答 ({"status":"ok"} 等)
```

### A-4. 確認手順（Agentホスト上で実施・結果をPlaneに貼付）

> 実行場所の凡例: `[A]`=Agentホスト、`[M]`=MCP Serverホスト、`[V]`=検証端末。
> 秘密鍵・生トークンは出力・チケットに貼らないこと。

```bash
# [A] 1. OS・カーネル・アーキテクチャ
lsb_release -a 2>/dev/null || cat /etc/os-release
uname -r
arch
# 期待: Ubuntu 22.04/24.04 または Rocky 9、x86_64

# [A] 2. ホスト名・名前解決・IP
hostname -f
getent hosts "$(hostname -f)"
ip -brief addr show
# 期待: FQDN が引けること、提供情報 (10.0.0.10 等) と一致すること

# [A] 3. 権限 (root / sudo)
id
id -u   # 期待: 0 (root 直実行の場合)
sudo -n true && echo "sudo-ok"
# 期待: root または sudo 可能な専用ユーザーであること

# [A] 4. 時刻同期 (監査ログ時刻の正確性)
timedatectl status | grep -E "System clock|NTP service|synchronized"
timedatectl show | grep NTPSynchronized
# chrony 利用時:
chronyc tracking 2>/dev/null | head -n 8 || systemctl status chrony* systemd-timesyncd* --no-pager | head -n 20
# 期待: synchronized: yes / NTPSynchronized=yes / chrony の Leap status が Normal
```

```bash
# [A] 5. Agent 導入後の到達性 (導入実施後に確認。ポート9443)
ss -tlnp | grep 9443
curl -sk https://127.0.0.1:9443/v1/health; echo
# 期待: {"status":"ok"} 等の 200 応答 (Agent README §Quick Start。ポートは9443に読替)

# [M] 6. MCP Serverホストからの到達性 (firewall越し。ポート9443)
curl -sk https://<agent-fqdn-or-ip>:9443/v1/health; echo
nc -zv <agent-fqdn-or-ip> 9443
# 期待: 200 応答 / succeeded。失敗時は D節 (firewall) を見直す

# [V] 7. プリフライト (MCP Server側から)
cd mcp-server
python scripts/verify_env.py --network   # "Agent到達性 [<node-id>]" が PASS であること
```

Plane貼付テンプレ (A):
```
[A] OS: <lsb_release結果> / kernel <uname -r> / arch <arch>
[A] FQDN: <hostname -f> / IP: <ip addr結果>
[A] 権限: <id結果> / sudo-ok: <yes/no>
[A] NTP: <synchronized: yes/no> (<chrony|timesyncd>)
[A] Agent到達: <curl結果> / MCP Serverから: <curl/nc結果>
[A] verify_env: <Agent到達性 PASS/FAIL>
```

#### A-5. 実施記録 (acemagic01, 2026-09-10)

- ホスト: `acemagic01` / OS: Ubuntu 24.04.3 LTS (noble) / NTP: NTPSynchronized=yes
- 権限: root 確認 (当初 uid=1000/sudo-ng → root で解消)
- ポート: 既定8443は docker-proxy (pid=3570/3577) が占有 → **9443** へ変更
  (Agent `agent.listen: ":9443"` + MCP `servers[].url` + firewall の3点連動)
- Agent更新: `/usr/local/bin/lrm-mcp-agent` を最新ビルドへ更新
  (9/7 00:20, 9580824 bytes → 9/10 01:00, 9596484 bytes)
- 再起動後: pid=25332 active / `*:9443` LISTEN /
  `curl -sk https://127.0.0.1:9443/v1/health` → `{"agent_version":"0.1.0","hostname":"lrm-mcp-agent","status":"ok"}`
- 判定: A-1 (4○全合格) / A-4 (到達○)。A-3導入は不要 (稼働中+最新化済み)
- 次工程: MCP Server側の node登録 (`https://<acemagic01>:9443`) + firewall 9443許可 +
  `verify_env.py --network` の「Agent到達性」PASS確認

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

### B-4. 確認手順（MCP Serverホスト上で実施・結果をPlaneに貼付）

```bash
# [B] 1. OS・Python・systemd
cat /etc/os-release | grep -E "^(NAME|VERSION)="
python3 --version   # 期待: 3.10 以上
systemctl --version | head -n 2

# [B] 2. 専用ユーザー・権限
id linux-mcp
sudo -n true && echo "sudo-ok"

# [B] 3. systemd unit の配置と起動状態
ls -l /etc/systemd/system/linux-mcp-console.service /etc/systemd/system/linux-mcp-http.service
sudo systemctl daemon-reload
systemctl is-enabled linux-mcp-console.service linux-mcp-http.service
systemctl is-active linux-mcp-console.service linux-mcp-http.service
# 期待: enabled / active。失敗時は次で原因特定:
journalctl -u linux-mcp-console.service --no-pager -n 50
journalctl -u linux-mcp-http.service --no-pager -n 50

# [B] 4. listen ポート (管理NW/利用者NW分離の前提)
ss -tlnp | grep -E ":(8080|8090)"
# 期待: 127.0.0.1:8080 / 127.0.0.1:8090 (0.0.0.0 の場合は D節で要是正)

# [B] 5. コンソール応答
curl -s http://127.0.0.1:8080/api/meta; echo
# 期待: HTTP 200 の JSON (verify_env.py の「コンソール到達性」も PASS になること)

# [B] 6. データ・秘密ファイルの権限
ls -ld /opt/linux-remote-management-mcp/mcp-server/data
stat -c "%a %U:%G %n" /opt/linux-remote-management-mcp/mcp-server/data
ls -l /etc/linux-mcp-server/env
stat -c "%a %n" /etc/linux-mcp-server/env
# 期待: data=700、env=600 (Operations.md §1.4)

# [B] 7. リバースプロキシ有無 (ある場合のみ)
nginx -T 2>/dev/null | grep -E "listen|server_name|proxy_pass|ssl_certificate" | head -n 20
# 期待: TLS終端位置 (proxy/console のどちらか) が特定できること

# [V] 8. プリフライト
cd mcp-server
python scripts/verify_env.py --network   # 「コンソール到達性」PASS を確認
```

Plane貼付テンプレ (B):
```
[B] OS: <NAME/VERSION> / Python: <python3 --version> / systemd: <version>
[B] unit: console=<active/inactive> http=<active/inactive> (enable=<yes/no>)
[B] listen: <ss結果> / /api/meta: <HTTPコード>
[B] 権限: data=<700?> env=<600?> / proxy: <有(終端位置)/無>
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

### C-5. 確認手順（受領物の検収・結果をPlaneに貼付）

> ⚠️ 秘密鍵の中身・パスフレーズは出力・チケットに貼らない。`subject/issuer/SAN/期限/検証結果` のみ貼る。

```bash
# [V] 1. 受領物の一覧 (期待: ca.crt / agent.crt / agent.key / client.crt / client.key / crl.pem(任意))
ls -l ca.crt agent.crt agent.key client.crt client.key crl.pem 2>&1

# [V] 2. 各証明書の subject / issuer / 期限
for f in ca.crt agent.crt client.crt; do
  echo "=== $f ==="
  openssl x509 -in "$f" -noout -subject -issuer -dates
done
# 期待: issuer が CA の subject と一致、notAfter が未来 (P2-12 は残14日以上推奨)

# [V] 3. SAN (Agent サーバー証明書)
openssl x509 -in agent.crt -noout -ext subjectAltName
# 期待: DNS:agent-prod-01.example.local, IP:10.0.0.10 を含む (C-2 の表と一致)

# [V] 4. チェーン検証 (CA署名の正当性)
openssl verify -CAfile ca.crt agent.crt    # 期待: agent.crt: OK
openssl verify -CAfile ca.crt client.crt   # 期待: client.crt: OK

# [V] 5. 証明書と秘密鍵のペア一致 (modulus ハッシュ比較。秘密鍵自体は表示しない)
openssl x509 -in agent.crt -noout -modulus | openssl md5
openssl rsa  -in agent.key -modulus -noout 2>/dev/null | openssl md5
# 期待: 2つのハッシュが一致。client 側も同様:
openssl x509 -in client.crt -noout -modulus | openssl md5
openssl rsa  -in client.key -modulus -noout 2>/dev/null | openssl md5

# [V] 6. 失効配布物 (ある場合)
openssl crl -in crl.pem -noout -text 2>/dev/null | grep -E "Last Update|Next Update" | head -n 4
# OCSP の場合: responder URL を記録 (openssl x509 -in agent.crt -noout -ocsp_uri)

# [B/A] 7. 配置後の権限 (MCP Server / Agent ホスト)
stat -c "%a %U:%G %n" /opt/linux-mcp/client.crt /opt/linux-mcp/client.key
stat -c "%a %U:%G %n" /etc/linux-agent/server.crt /etc/linux-agent/server.key /etc/linux-agent/ca.crt
# 期待: *.crt=644、*.key=600 (doc/mTLS.md §3.2/§4.2)

# [B] 8. プリフライト (MCP Server側)
cd mcp-server
python scripts/verify_env.py   # 「mTLS クライアント証明書」が鍵一致OK・期限残存で PASS/WARN のいずれか
```

Plane貼付テンプレ (C):
```
[C] 受領: ca.crt=<○/×> agent.crt/key=<○/×> client.crt/key=<○/×> crl=<有/無/OCSP(URL)>
[C] agent.crt: subject=<...> issuer=<...> notAfter=<...> SAN=<...>
[C] verify: agent=<OK/NG> client=<OK/NG> / 鍵ペア一致: agent=<一致/不一致> client=<一致/不一致>
[C] 配置権限: crt=<644?> key=<600?> / verify_env mTLS: <PASS/WARN/FAIL>
```

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
# Agent ホスト (ポート9443。既定8443はdocker-proxy占有のため変更)
sudo ufw allow from 10.0.0.20 to any port 9443 proto tcp      # Agent: MCP Serverのみ
sudo ufw default deny incoming
```

### D-3. 確認手順（境界の実測・結果をPlaneに貼付）

```bash
# [B/A] 1. 経路とアドレス (申告CIDRとの突合用)
ip route show
ip -brief addr show

# [B/A] 2. firewall の現状 (いずれか。操作権限のある方式で)
sudo ufw status numbered 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
sudo iptables -L -n --line-numbers 2>/dev/null | head -n 40
# 期待: 管理NW→8080、利用者NW→8090、MCP Server→Agent:9443 のみ許可

# [B/A] 3. listen アドレス (0.0.0.0 露出の有無)
ss -tlnp | grep -E ":(8080|8090|9443)"
# 期待: console=127.0.0.1:8080 (管理NW公開はproxy経由)、mcp=利用者NW向け、agent=9443

# [M→A] 4. MCP Server → Agent の疎通 (ポート9443)
nc -zv <agent-ip> 9443
curl -sk -o /dev/null -w "%{http_code}\n" https://<agent-ip>:9443/v1/health
# 期待: open / 200 (401/403 も「到達OK」として扱う。verify_env.py と同じ判定)

# [管理端末→M] 5. 管理NW → console の疎通
curl -s -o /dev/null -w "%{http_code}\n" http://<mcp-server-ip>:8080/api/meta
# 期待: 200。利用者NWからは 8080 が不通であることも確認 (D-1 の分離確認):
# (利用者NW端末で) nc -zv <mcp-server-ip> 8080  # 期待: 失敗 (拒否/タイムアウト)

# [利用者NW→M] 6. 利用者NW → MCP HTTP の疎通
ss -tlnp | grep 8090
# (利用者NW端末で) nc -zv <mcp-server-ip> 8090  # 期待: 成功

# [V] 7. プリフライト (設定面の自動判定)
cd mcp-server
python scripts/verify_env.py   # 「listen address」「Agent TLS検証」「コンソール認証」を確認
grep -E "host:|tls_verify|auth_mode" config.yml
# 期待: console/mcp の host が 0.0.0.0 でない、tls_verify=true、auth_mode=oidc or Basic資格あり
```

Plane貼付テンプレ (D):
```
[D] 管理NW: <CIDR> / 利用者NW: <CIDR> / VPN: <有/無> / firewall方式・操作者: <ufw/firewalld/ACL・氏名>
[D] firewall現状: <ufw status / firewall-cmd 要約の貼付>
[D] listen: <ss結果> / M→A疎通: <nc/curl結果> / 管理→console: <HTTPコード> / 利用者→8080不通: <確認済/未>
[D] verify_env: listen=<PASS/WARN> TLS検証=<PASS/WARN> 認証=<PASS/WARN>
```

---

## E. systemd 導入環境（root 権限）

- 対象: **MCP Server サーバー（B）と Agent サーバー（A）の両方**
- 確認事項:
  - systemd が利用可能（`systemctl --version`）
  - `linux-mcp`（MCP Server）と `lrm-mcp-agent`（Agent）の専用ユーザー作成権限
  - `/etc/systemd/system/` へ unit を配置する権限

### E-1. 確認手順（両ホスト共通・結果をPlaneに貼付）

```bash
# 1. root / sudo (破壊なしの読み取り確認)
whoami
id -u   # 期待: 0
sudo -n true && echo "sudo-ok"

# 2. init が systemd であること (コンテナ等では PID1 が異なる場合あり)
ps -p 1 -o comm=
systemctl --version | head -n 2
systemd-detect-virt 2>/dev/null || echo "virt: bare-metal/unknown"
# 期待: comm=systemd。container/docker の場合は unit 配置先ホストでの再実施が必要

# 3. 専用ユーザー (導入前は「不在」で正常。導入後は存在)
id linux-mcp      # [B] MCP Serverホスト
id lrm-mcp-agent  # [A] Agentホスト

# 4. unit 配置権限の実証 (空ファイルではなく実unitで。配置後の確認)
ls -l /etc/systemd/system/linux-mcp-*.service /etc/systemd/system/lrm-mcp-agent.service 2>&1
# 書き込み権限の事前確認 (安全な touch 検証。残さない):
sudo touch /etc/systemd/system/.writetest && sudo rm /etc/systemd/system/.writetest && echo "unit-dir-writable"

# 5. 有効化・起動の確認 (導入実施後)
sudo systemctl daemon-reload
systemctl is-enabled linux-mcp-console.service linux-mcp-http.service 2>&1  # [B]
systemctl is-active  linux-mcp-console.service linux-mcp-http.service 2>&1  # [B]
systemctl is-enabled lrm-mcp-agent 2>&1   # [A]
systemctl is-active  lrm-mcp-agent 2>&1   # [A]
# 期待: enabled/active。失敗時は:
journalctl -u linux-mcp-console.service --no-pager -n 30 2>&1 | tail -n 30  # [B]
journalctl -u lrm-mcp-agent --no-pager -n 30 2>&1 | tail -n 30               # [A]

# 6. プリフライト (unit ファイルの存在チェックに対応)
cd mcp-server
python scripts/verify_env.py   # 「systemd unit」「運用スクリプト」の項目を確認
```

Plane貼付テンプレ (E):
```
[E] ホスト: <B/A> / whoami: <...> (uid=<...>) / sudo: <ok/ng>
[E] PID1: <systemd?> / systemctl: <version> / virt: <...>
[E] 専用ユーザー: <存在/不在> / unit配置権限: <writable/ng>
[E] unit状態: <enabled/active の実測値> / verify_env: <systemd unit PASS/WARN>
```

---

## F. 最終確認（事前準備完了判定）

### F-1. プリフライトの実行（判定前の必須ゲート）

```bash
cd mcp-server
python scripts/verify_env.py --network
# 期待: FAIL=0。WARN は該当タスク (P0-2/P2-12/P2-10等) の前提として F-2 に記録する。
# JSONで記録する場合:
python scripts/verify_env.py --network --json > /tmp/verify_env_$(date +%F).json
# 要約行 (summary: PASS=x WARN=y FAIL=z SKIP=w) をPlaneに貼る
```

```text
[ ] A: 別Linuxサーバー（Agent導入用）が提供された（A-4 の貼付あり）
[ ] B: 本番MCP Server導入サーバーが提供された（B-4 の貼付あり）
[ ] C: mTLS用証明書一式（CA / server / client / CRL）が発行・受け渡しされた（C-5 の貼付あり）
[ ] D: ネットワーク境界情報（管理NW/利用者NW/VPN/firewall権限）が判明した（D-3 の貼付あり）
[ ] E: systemd 導入が可能（root権限）である（E-1 の貼付あり）
[ ] F-1: verify_env.py --network で FAIL=0（要約行を貼付）
```

すべて `[x]` になったら、Plane 事前準備チケットに記録し、**P0-2 → 3.1 → P1-6 → P2-10 → P2-12** の順に実環境検証を実施する。

### F-2. Plane 事前準備チケットへの記録テンプレ

```text
[事前準備 完了報告] <日付> 実施者: <氏名>
- A: <OS/FQDN/IP/権限/NTP/到達性の要約> (詳細は A-4 貼付)
- B: <OS/Python/unit/listen//api/meta の要約> (詳細は B-4 貼付)
- C: <受領物○×/notAfter/SAN/verify/鍵ペア一致の要約> (詳細は C-5 貼付)
- D: <CIDR/VPN/firewall方式/疎通結果の要約> (詳細は D-3 貼付)
- E: <PID1/systemd/権限/unit状態の要約> (詳細は E-1 貼付)
- verify_env: summary: PASS=<x> WARN=<y> FAIL=0 SKIP=<z> (JSON添付任意)
- 残WARNと対応方針: <例: mTLS未配置のためP0-2実施時に配置する>
- 次工程: P0-2 → 3.1 → P1-6 → P2-10 → P2-12 の順に実環境検証へ
```

---

## 参考

- mTLS 設定詳細: `doc/mTLS.md`
- 実環境検証手順全般: `doc/EnvVerification.md`
- 導入・運用: `doc/Operations.md`
- Agent セットアップ: `lrm-mcp-agent/README.md` / `lrm-mcp-agent/scripts/setup.sh`
- MCP Server セットアップ: `mcp-server/scripts/setup.sh`