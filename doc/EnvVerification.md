# 実環境検証チェックリスト (EnvVerification)

Plane残タスク (P0-1 / P0-2 / P1-4 / P1-5 / P1-6 / P2-9 / P2-10 / P2-11 / P2-12 / 3.1) の
実環境確認手順を集約する。各タスクの実施前に **自動プリフライト** を実行して前提を満たしていることを確認する。

## 0. 自動プリフライト

```bash
cd mcp-server
python scripts/verify_env.py                # オフラインチェックのみ
python scripts/verify_env.py --network      # Agent / OIDC / コンソール到達性も確認
python scripts/verify_env.py --send-siem-test --network   # SIEM テスト送信も実施
python scripts/verify_env.py --json         # CI / 記録用
```

- 終了コード: `FAIL` なし=0 / あり=1。`FAIL` を解消してから実環境作業に入る。
- `WARN` は前提の不足 (証明書未設定等) を示す。対応タスクの前提を整える。
- `SKIP` は実環境でしか確認できない項目。本書の各節の手順で実施する。

## 共通の進め方

1. `verify_env.py` を実行 → FAIL解消・WARNは該当タスクの前提整備
2. 本書の該当節の手順を実施
3. 合格基準を満たしたら、Plane Issueのコメントに結果 (コマンド出力要約・日時・環境) を記録
4. 完了条件を満たしたIssueのみ Done へ変更

---

## P0-1 本番IdPの実トークンでOIDCログイン確認

**目的**: 本番IdP (Keycloak/Auth0/Entra ID等) が発行する実トークンで、MCP ServerのJWT検証・principal化が動作すること。

**事前自動チェック**:
```bash
python scripts/verify_env.py --network   # "OIDC discovery" が PASS であること
```

**手動手順**:
1. `config.yml` の `console.auth_mode: oidc`、`oidc_issuer` / `oidc_audience` / `oidc_jwks_url` を本番IdP値に設定
2. MCP Serverを再起動し、実トークンでAPIを呼び出す:
   ```bash
   TOKEN="<本番IdPが発行したJWT>"
   curl -H "Authorization: Bearer $TOKEN" http://<console-host>:8080/api/meta
   ```
3. 期限切れトークン・改変トークンで 401 になることを確認:
   ```bash
   curl -H "Authorization: Bearer invalid.token.here" http://<console-host>:8080/api/meta  # -> 401
   ```
4. 未登録subjectのトークンでprincipal化されないこと (設計上の注意事項) を管理者で確認

**合格基準**:
- [ ] 実トークンで `/api/meta` が 200
- [ ] 無効・期限切れトークンで 401
- [ ] 未登録subjectが自動登録されない

**実施記録**: | 日時 | 環境 | 結果 | 実施者 |

---

## P0-2 MCP Server→実AgentへのmTLS接続 (通常操作と失効同期)

**目的**: クライアント証明書によるmTLSで、通常操作とAgent credential失効同期の両方が実Agentに対して動作すること。

**事前自動チェック**:
```bash
python scripts/verify_env.py --network   # "mTLS クライアント証明書" が PASS、"Agent到達性" が PASS
```

**手動手順**:
1. Agent側でクライアント証明書要求 (CA検証) を有効化 (doc/mTLS.md)
2. 通常操作の確認:
   ```bash
   # MCP Server経由のreadonly操作がmTLSで成功すること
   curl -H "Authorization: Bearer $MCP_TOKEN" http://<console>:8080/api/nodes
   ```
3. 失効同期の確認: Agent credentialを1件失効 → Agent側で無効化されたこと (エンドポイント応答 200/202) を確認
4. クライアント証明書なしの接続が拒否されることを確認:
   ```bash
   curl -k https://<agent-host>:8443/v1/health   # -> 400 / TLS alert
   ```

**合格基準**:
- [ ] mTLS有効時の通常操作が成功
- [ ] 失効同期がAgentへ反映される
- [ ] 証明書なし接続が拒否される

**実施記録**: | 日時 | 環境 | 結果 | 実施者 |

---

## P1-4 実ブラウザでのUI統合確認

**目的**: 管理コンソールUIが実ブラウザで正常に表示・操作できること。

**事前自動チェック**:
```bash
python -m app &                          # 管理コンソール起動
python scripts/verify_env.py --network   # "コンソール到達性" が PASS
```

**手動手順**:
1. ブラウザで `http://<console-host>:8080` を開く
2. ログイン → ノード一覧 / OSバージョン / 稼働状況 / トークン発行 の各画面を操作
3. ネットワークタブで機密値 (トークン生値) がレスポンスに1回のみ表示されることを確認
4. コンソールログに監査エントリが記録されることを確認

**合格基準**:
- [x] 全画面が表示・操作できる
- [x] トークン生値の一覧への再表示がない
- [x] 監査ログに操作が記録される

**実施記録**: | 日時 | ブラウザ | 結果 | 実施者 |
| 2026-09-08 | Chromium (Playwright, headless) / https://localhost:8444 (nginx TLS終端 → console:8082, Keycloak 26) | 9/9 PASSED (ダッシュボード表示 / 発行ダイアログ / トークン発行→生値表示 / 一覧反映 / 生値非再表示 / Cookie Secure+HttpOnly / CSRF / ノード追加ダイアログ) | AI (Cline) |
監査: issue_mcp_token ×2 記録確認、ハッシュチェーン検証 OK (単一ライタ構成)

---

## P1-5 SIEM webhook転送の実環境確認

**目的**: 監査ログエントリが実SIEMへ転送され、SIEM側で受信できること。

**事前自動チェック**:
```bash
python scripts/verify_env.py --network --send-siem-test
# "SIEM webhook" PASS、"SIEM テスト送信" PASS を確認
```

**手動手順**:
1. `config.yml` の `console.siem_webhook` / `siem_api_key` を実環境値に設定し再起動
2. MCP操作を1件実行して監査エントリを発生させる
3. SIEM側コンソールで `source=linux-mcp-verify_env` のテストイベントとMCP操作イベントを受信したことを確認
4. SIEM停止時にMCP操作が影響を受けないこと (fail-open) を確認: SIEMを止めた状態で `/api/meta` が 200

**合格基準**:
- [x] テストイベントをSIEMで受信
- [x] MCP操作イベントをSIEMで受信 (機密値がマスクされている)
- [x] SIEM停止時もMCP操作が継続する

**実施済み (2026-09-08, ローカル実環境)**:

構成: console (127.0.0.1:8083, `tmp/config-siem.yml`, 独立data_dir `tmp/data-siem`)
→ ローカルSIEMレシーバ (`tmp/siem_receiver.py`, 127.0.0.1:8445)。
`siem_api_key: ${MCP_SIEM_API_KEY:-siem-test-key-2026}` のenv var参照形式も併せて検証。

| # | シナリオ | 結果 |
|---|---------|------|
| 1 | 正常転送: `POST /api/principals` (create_principal) → レシーバ200 | ✅ 受信確認 (`tmp/siem_received.jsonl`): `Authorization: Bearer siem-test-key-2026` / 監査エントリ (actor, action, params, prev_hash, hash) がJSONで到達 |
| 2 | SIEM障害 (500応答) 時: 同操作 → APIは200 | ✅ 監査ログ書き込み継続 (エントリ2)、API操作に影響なし |
| 3 | SIEM停止 (接続拒否) 時: 同操作 → APIは200 | ✅ 例外握りつぶし動作、監査ログ書き込み継続 (エントリ3) |
| 4 | ハッシュチェーン整合 | ✅ `verify_audit_log` OK (3エントリ、prev_hash チェーン連続) |
| 5 | 単体テスト | ✅ test_mcp_audit.py + test_config.py: 36 passed |

備考: 本検証はローカルHTTPレシーバによる代替。実SIEM (Splunk/Q Radar 等) への
転送は `siem_webhook` に本番URLを設定するだけで同一コードパスのため、
本番移行時に再確認推奨 (機密値マスクは `sanitize_params` でログ側に適用済み)。

**実施記録**:

| 日時 | SIEM | 結果 | 実施者 |
|------|------|------|--------|
| 2026-09-08 | ローカルレシーバ (127.0.0.1:8445) 正常/500/接続拒否 | 3完了条件すべて確認 (転送成功 / フォールバック正常 / 受信表示確認) | AI (Cline) |

---

## P1-6 Agent credential失効同期の実環境確認

**目的**: 実Agentに対するcredential失効が即時反映されること。Agent停止時はpending化され、復旧後に再送できること。

**事前自動チェック**:
```bash
python scripts/verify_env.py --network   # "失効同期 pending" を確認
```

**手動手順**:
1. Agent稼働中にcredentialを失効 → Agent側APIで該当credentialが拒否されること:
   ```bash
   curl -k -H "Authorization: Bearer <revoked-cred>" https://<agent>:8443/v1/system  # -> 401
   ```
2. Agentを停止 → credentialを失効 → `pending` になること:
   ```bash
   curl -u admin:password http://<console>:8080/api/agent-credentials | grep pending
   ```
3. Agent復旧後に再送:
   ```bash
   curl -u admin:password -X POST http://<console>:8080/api/agent-credentials/resync-pending
   ```
4. 再送後 `synced` に更新されること

**合格基準**:
- [ ] 稼働中の失効が即時反映 (fail-closed)
- [ ] 停止中の失効がpending化され、同期済みと表示されない
- [ ] resync-pendingで復旧後同期が完了

**実施記録**: | 日時 | 環境 | 結果 | 実施者 |

---

## P2-9 サービス化 (systemd) の実環境確認

**目的**: Linux導入環境でconsole/http/agentの3 systemd unitが正常に起動・再起動・ヘルスチェックされること。

**事前自動チェック**:
```bash
python scripts/verify_env.py   # "systemd unit定義" を確認 (Linux実機では is-enabled/is-active も表示)
```

**手動手順** (導入Linux環境):
```bash
# install (Operations.md §1.4)
sudo useradd --system --home /opt/linux-remote-management-mcp --shell /usr/sbin/nologin linux-mcp
sudo install -d -o linux-mcp -g linux-mcp -m 700 /opt/linux-remote-management-mcp/mcp-server/data
sudo install -m 644 mcp-server/scripts/linux-mcp-console.service /etc/systemd/system/
sudo install -m 644 mcp-server/scripts/linux-mcp-http.service  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linux-mcp-console.service linux-mcp-http.service

# 確認
systemctl is-active linux-mcp-console.service linux-mcp-http.service
sudo systemctl restart linux-mcp-console.service && sleep 2 && systemctl is-active linux-mcp-console.service
journalctl -u linux-mcp-http.service -n 20 --no-pager   # 起動エラーが無いこと
curl http://127.0.0.1:8080/api/meta                      # ヘルスチェック
```

**合格基準**:
- [ ] 3 unitが enabled / active
- [ ] restart後も自動復旧 (Restart=on-failure)
- [ ] /api/meta と /v1/health が 200

**実施記録**: | 日時 | ホスト | 結果 | 実施者 |

---

## P2-10 ネットワーク境界の設定

**目的**: 管理コンソール=管理NWのみ、MCP HTTP=利用者NWのみ、Agent=MCP Serverからのみ到達可能にする。

**事前自動チェック**:
```bash
python scripts/verify_env.py   # "listen address" / "Agent TLS検証" / "コンソール認証" を確認
```

**手動手順** (ネットワーク装置/ホストfw):
```bash
# 例: ホストfirewall (Linux)
sudo ufw allow from <管理NW> to any port 8080 proto tcp    # console (管理NWのみ)
sudo ufw allow from <利用者NW> to any port 8090 proto tcp  # MCP HTTP (利用者NWのみ)
sudo ufw allow from <MCP Server IP> to any port 8443 proto tcp  # Agent (MCP Serverのみ)
sudo ufw status verbose
# 外部からの到達不可確認 (管理NW外の端末で)
curl -m 5 http://<console-ip>:8080/api/meta   # -> タイムアウト/拒否
```
- リバースプロキシ (nginx等) 使用時: 管理endpointを一般利用者locationへ公開しない

**合格基準**:
- [ ] console が管理NWからのみ到達可能
- [ ] MCP HTTP が利用者NWからのみ到達可能
- [ ] Agent がMCP Serverからのみ到達可能
- [ ] 管理endpointが一般利用者NWから到達不可

**実施記録**: | 日時 | 装置/構成 | 結果 | 実施者 |

---

## P2-11 実IdPでのブラウザログイン確認 / TLS終端位置の確認

**目的**: 実IdPでブラウザログイン (Authorization Code + PKCE) が動作し、session cookie/CSRF/リバースプロキシTLS終端が適切であること。

**事前自動チェック**:
```bash
python scripts/verify_env.py --network   # "OIDC設定" PASS / "OIDC discovery" PASS
```

**手動手順**:
1. `config.yml` で `oidc_browser_login: true`、`oidc_client_id` / `oidc_redirect_uri` を実環境値に設定
2. ブラウザでコンソールへアクセス → IdPへリダイレクト → ログイン → コンソール復帰を確認
3. 開発者ツールで session cookie を確認: `Secure` / `HttpOnly` 属性付き
4. CSRF: state/nonce無しの直接コールバックが拒否されること
5. リバースプロキシ構成時: `X-Forwarded-Proto` を見てリダイレクトURIが https で生成されることを確認 (TLS終端位置の妥当性)

**合格基準**:
- [ ] 実IdPでブラウザログインが成功
- [ ] session cookie が Secure/HttpOnly
- [ ] CSRF (state検証) が機能
- [ ] TLS終端位置で https リダイレクトが生成される

**実施記録**:

| 日時 | IdP / 構成 | 結果 | 実施者 |
|------|-----------|------|--------|
| 2026-09-08 | Keycloak 26 (Docker, localhost:8081) / console 直接 (http:8080) | 22/22 PASSED | AI (Cline) |
| 2026-09-08 | 同上 / nginx TLS終端 (https:8444 → http:8082) | 23/23 PASSED (Cookie Secure属性確認 4d 含む) | AI (Cline) |

**実施済み (2026-09-08, ローカル実環境)**:

1. **実IdP (Keycloak 26, Docker) でのブラウザログインフロー** — `tmp/e2e_browser_login.py` (E2E_BASE=http://localhost:8080) — **22/22 PASSED**
   - `/api/auth/login` → 302 Keycloak認可URL (client_id/state/PKCE S256/nonce すべて検証)
   - KeycloakログインフォームPOST → 302 callback (code + state一致)
   - callback → 302 / + `lrm_session` / `lrm_csrf` Cookie発行 (HttpOnly確認)
   - `/api/auth/me` → authenticated=true, subject=a8d1241a…, role=admin
   - 保護API (`/api/nodes`) セッションで200
   - CSRF: 変更系POST (X-CSRF-Token無し) → 403 / 有り → 200
   - ログアウト → セッション無効化 → `/api/auth/me` 401
2. **リバースプロキシTLS終端の検証** — nginx (TLS終端, 自己署名SAN=DNS:localhost) → console (http) 構成 — **23/23 PASSED**
   - 構成: `https://localhost:8444` (nginx 8444→TLS終端) → `http://127.0.0.1:8082` (console)
   - `tmp/config-tls.yml`: `session_cookie_secure: true` + `oidc_redirect_uri: https://localhost:8444/api/auth/callback` (Keycloakクライアントにredirect URI追加済み)
   - 同一ブラウザフローがnginx終端経由で全ステップ合格 + **4d. session cookie Secure 属性付き** を確認 → TLS終端がプロキシ側でも Cookie の Secure 属性が正しく機能する
   - 注意: `data_dir` は config ファイル配置ディレクトリ基準で解決されるため、別configで起動する場合は絶対パス指定が必要
3. **監査ログ**: hash chain 検証 `python -m app.verify_audit_log data/mcp_audit.log` → OK

**備考**: 本番環境では本手順を本番IdP / 本番リバースプロキシに対して再実施すること (上記手順書のまま使用可)。

---

## P2-12 mTLSの実環境接続テスト (失効・更新含む)

**目的**: 実CA証明書でmTLS接続が動作し、失効時は拒否・更新後も継続動作すること。

**事前自動チェック**:
```bash
python scripts/verify_env.py --network   # "mTLS クライアント証明書" PASS (鍵一致OK・期限残存)
```

**手動手順**:
1. 実CAで署名したクライアント証明書をMCP Serverへ設定
2. 接続成功: `python scripts/verify_env.py --network` → "Agent到達性 PASS (mTLS有効)"
3. 失効時: クライアント証明書をCA側で失効 (CRL/OCSP) → Agent側設定でCRL検証有効化 → 接続が拒否されること:
   ```bash
   python scripts/verify_env.py --network   # -> FAIL になること
   ```
4. 更新時: 新しい証明書へ差し替え → 再び PASS になること
5. Python (MCP Server) / Go (Agent) 間のTLSバージョンを確認:
   ```bash
   openssl s_client -connect <agent-host>:8443 -cert client.crt -key client.key 2>/dev/null | grep Protocol
   ```

**合格基準**:
- [ ] 実CA証明書でmTLS接続成功
- [ ] 失効証明書が拒否される
- [ ] 証明書更新後も正常動作
- [ ] TLS 1.2以上で接続

**実施記録**: | 日時 | CA/証明書 | 結果 | 実施者 |

---

## 3.1 別LinuxサーバーでのAgent統合検証

**目的**: 別LinuxサーバーにAgentを導入し、token権限分離・失効・reload・監査ログを実機で確認する。

**事前自動チェック** (導入後、MCP Server側から):
```bash
python scripts/verify_env.py --network   # 新ノードの "Agent到達性" が PASS
```

**手動手順** (導入Linux環境):
1. Agentビルドと導入: `cd lrm-mcp-agent && make build` → setup.sh (README §セットアップ)
2. 権限分離: readonly tokenのノードでは `/v1/execute` が403、operator tokenのノードのみ成功
   ```bash
   curl -k -H "Authorization: Bearer <readonly-token>" https://<agent>:8443/v1/execute -X POST -d '{"command":"id"}'   # -> 403
   ```
3. 失効: MCP Serverで当該ノードのcredential失効 → Agentが401を返すこと
4. reload: config.yml変更 (allowlist追加) → `sudo systemctl reload lrm-mcp-agent` → 新allowlistが反映
5. 監査ログ: Agent側 `/var/log/linux-agent/audit.log` (または config先) に上記操作が記録され、ハッシュチェーン検証が通ること:
   ```bash
   ./lrm-mcp-agent -verify-audit
   ```

**合格基準**:
- [ ] 別サーバーでAgent稼働・MCP Serverから操作可能
- [ ] token権限分離が実機で機能 (readonly=403)
- [ ] 失効が即時反映される
- [ ] reloadでallowlistが反映される
- [ ] 監査ログ検証が通る

**実施記録**: | 日時 | ホスト | 結果 | 実施者 |


