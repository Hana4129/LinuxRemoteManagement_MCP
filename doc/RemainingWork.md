# 残作業一覧

Linux Remote Management MCP の認証・認可分離に関する残作業をまとめる。

## 現在の実装済み範囲

- 管理コンソールと MCP HTTP の別プロセス・別ポート化
- MCP HTTP / stdio の明示的な Bearer token 認証
- principal、server、scope による基本的な権限チェック
- principal の作成、権限付与、権限失効、無効化
- OIDC JWT の署名、issuer、audience、期限、subject 検証
- Agent 接続 credential の分離管理
- Agent token の管理 endpoint による即時失効
- Agent管理失効 endpoint のGoテストを追加（ローカル環境ではGo未実行）
- 管理操作の admin role 制限
- 管理コンソールのAccessタブによるprincipal・権限・Agent credential管理
- 承認APIで認証済みprincipalを承認者として記録
- MCP承認要求で認証済みprincipalを要求者として記録
- 管理コンソールの同一origin CSRF検査
- 管理コンソール静的アセットのバージョン付きキャッシュ制御
- Basic認証アカウントをadmin principalとして扱う認証主体統一
- 管理コンソールのMCP Bearerトークン認証 (principal紐付けトークンのRBAC強制・無効/未紐付けトークンの401拒否)
- Python テスト 114 件

## 優先度 P0: 本番導入前に必要

### 1. OIDC の本番接続確認

**内容**

- 利用する IdP を決定する
- `issuer`、`audience`、JWKS URL を本番値に設定する
- リバースプロキシ配下で Authorization header が正しく転送されることを確認する
- IdP の subject と事前登録 principal の運用手順を決める
- JWKS 到達不能、鍵ローテーション、issuer/audience 不一致時の挙動を確認する

**完了条件**

- 本番IdPの実トークンで管理コンソールへログインできる
- 未登録 subject が `403` になる
- 期限切れ、署名不正、audience 不一致の token が `401` になる
- IdPの鍵ローテーション後もキャッシュ更新で検証できる

### 2. AgentとのmTLS構成確認

**内容**

- MCP Server用クライアント証明書を発行する
- Agent側 `client_ca_file` を設定する
- MCP Server側 `client_cert` / `client_key` を設定する
- Agentの管理 endpoint がPrivate NetworkまたはmTLS経由だけで到達可能であることを確認する

**完了条件**

- 証明書なしのAgent管理 endpointアクセスが拒否される
- 不正なクライアント証明書が拒否される
- MCP Serverから通常操作と失効同期の両方が成功する

### 3. Agent側Goテストとビルド

**内容**

- Go 1.22以上を用意する
- Agentの管理失効 endpoint のテストを追加する
- token失効後に通常APIが `401` になることを確認する
- 設定reloadと管理失効が競合しても失効状態が壊れないことを確認する

**完了条件**

```text
go test ./...
go vet ./...
go build ./cmd/lrm-mcp-agent
```

が成功する。

### 3.1 別LinuxサーバーでのAgent統合検証

Goのunit testだけでは本番相当の通信経路を検証できないため、実際にMCP Serverとは別のLinuxサーバーへAgentを配置して検証する。

**推奨構成**

```text
検証端末 / MCP Client
					|
					v
MCP Server (管理コンソール + MCP HTTP)
					|
					| Private Network / VPN + HTTPS
					v
別Linux検証サーバー
	└── lrm-mcp-agent (systemd)
```

**検証項目**

- Agentを専用ユーザーで起動できる
- Agentのlisten portがMCP Serverからだけ到達可能である
- MCP ServerからAgentへのHTTPS接続が成功する
- Agent側Bearer tokenでreadonly/operatorの権限差が反映される
- MCP利用者A/Bのserver・scope権限が分離される
- 管理コンソールからAgent credentialを失効すると、Agentが即時に旧tokenを拒否する
- Agent停止中の失効要求がエラーとして表示される
- Agent再起動後も失効済みtokenが復活しない
- `config.yml` のhot reload中も認証状態が壊れない
- Agent audit logに認証成功、拒否、管理失効が記録される
- mTLS有効時に証明書なし・不正証明書の接続が拒否される
- systemd再起動、ログ出力、data directory権限が期待どおりである

**合格条件**

```text
MCP Server -> Agent health: success
readonly token -> readonly API: success
readonly token -> operator API: 403
revoked token -> any protected API: 401
revoked Agent credential -> direct Agent API: 401
without client certificate -> mTLS Agent API: TLS failure
```

この検証は開発PC上のlocalhostモックAgentでは代替しない。最低でも別VM、別物理サーバー、または別Linuxコンテナネットワークを使用する。

## 優先度 P1: 権限管理の完成

### 4. 管理コンソールUIへのprincipal管理追加

**状態: 実装済み。統合運用確認が残っている。**

**内容**

Accessタブに以下の操作を追加済み。

- principal一覧・作成
- role表示
- server/scope権限の付与
- principal無効化
- Agent credential登録・失効
- 失効確認ダイアログ

**完了条件**

- 管理者がAPIを直接呼ばずにprincipal作成、grant/revokeできる
- viewer/operatorが管理操作を実行できない
- tokenやcredentialの生値を一覧画面に再表示しない

残作業はブラウザ統合テスト、OIDCログイン状態での権限確認、レスポンシブ表示確認である。

Basic認証でのブラウザ初期表示とノード一覧描画はローカル環境で確認済み。残りはAccessタブの各操作を認証済みブラウザで実行する統合確認である。

### 5. 承認フローのprincipal対応

**状態: 実装済み。統合運用確認が残っている。**

**内容**

- OIDC認証時はJWTの `sub` を承認者として記録する
- MCP認証時はprincipalのsubjectを `requested_by` として記録する
- 承認APIの `approver` をリクエスト本文から受け取らない
- Basic認証時は固定主体 `console` として記録する
- requesterとapproverの同一人物承認を禁止するか方針を決める

**完了条件**

- 監査ログに要求者と承認者が正しく記録される
- 任意の表示名を送信して承認者を偽装できない
- 承認・却下・期限切れ・消費の全状態でprincipalが保持される

残作業はOIDC実環境での承認統合テストと、requester/approver分離方針の運用確認である。

### 6. principal単位の監査ログ

**状態: 管理操作とMCP操作の基本監査を実装済み。SIEM・統合監査確認が残っている。**

**内容**

- MCP tool実行ログにprincipal subject、principal ID、token IDを記録する
- 管理APIのgrant/revoke、token発行、credential失効を監査する
- OIDC token、生token、admin secretをログへ出さない

**完了条件**

- 操作単位で「誰が」「どのserverへ」「何を」「どの結果」が追跡できる
- 既存のハッシュチェーン、ローテーション、SIEM転送と整合する

principal作成、権限付与/失効、principal無効化、MCP token発行、Agent credential登録/失効を監査ログへ記録する処理を追加済み。秘密値は記録しない。

## 優先度 P1: Agent credential運用

### 7. Agent credentialの発行・配布フロー

**状態: 生成API・ローテーション (グラ期間つき) を実装済み。Secret Manager連携が残っている。**

**内容**

- `POST /api/agent-credentials/generate` でサーバー側 (CSPRNG) がtokenを生成し、生値はレスポンスに一度だけ返す (発行フローの標準化)
- `POST /api/agent-credentials/{id}/rotate` でローテーション。旧credentialはgrace期間中残存し、期間経過後は使用不可
- `GET /api/agent-credentials/{id}/rotations` でローテーション履歴を追跡 (rotated_by記録つき)
- `POST /api/agent-credentials/cleanup-grace-periods` でグラ期間経過credentialを完全失効
- token ID、scope、allowlistの対応はAgent設定 (`config.yml`) とcredentialレコード (`agent_token_id`) で管理
- Secret Managerからの直接登録は未対応 (生値の一時表示は `/generate` で最小化済み)

**完了条件の状況**

- 生credentialがGit、ログ、API一覧に出ない → 実装・テスト済み (一覧は生値を返さない)
- credentialの発行、配布、ローテーション、失効を追跡できる → 実装済み (監査ログ + rotations履歴)
- 古いcredentialのgrace期間と完全失効を確認できる → 実装・テスト済み

残作業はSecret Manager (Vault等) 連携と、実Agent環境でのローテーションE2E確認である。

### 8. 失効同期の障害時運用

**状態: 実装済み (fail-closed + pending再送)。実Agent環境での統合確認が残っている。**

**内容**

- Agent停止中に失効要求が失敗した場合の扱い: fail-closedを採用。Agentへの同期に失敗してもMCP Server側のローカル失効は必ず完了させ、`agent_sync_state=pending` として記録する
- 同期状態はagent_credentialsテーブルの `agent_sync_state` カラム (synced / pending / skipped) で管理し、credential一覧APIで表示する
- 失効要求の冪等性: Agentが404 (該当tokenが既に失効済みまたは未登録) を返した場合は同期成功として扱う。同じ失効要求の再送は安全
- Agent復旧時の再送API:
  - `POST /api/agent-credentials/{id}/resync` (単一credential)
  - `POST /api/agent-credentials/resync-pending` (pending全件一括)
- 再送でもAgentに到達できない場合はpendingのまま維持される (fail-closedの継続)
- 失効していないcredentialへのresyncは409で拒否する

**完了条件**

- Agent停止中でもMCP Server側で利用停止状態を正しく表示できる → 実装済み (enabled=0 + sync_state表示)
- Agent復旧後に失効が自動的に反映される → resync-pendingをsystemd timer / cronから定期実行することで実現 (手順はOperations.md 3.4参照)
- 同じ失効要求を複数回送っても安全である → 実装済み (404を冪等扱い、再試行テスト6件追加)

残作業は実Agent環境での統合確認 (Agent停止 → 失効 → 復旧 → resyncのE2E) である。

## 優先度 P2: 運用・品質

### 9. サービス化

**状態: Linux systemd unitを実装済み。導入環境でのパス・ユーザー・権限確認が残っている。**

- 管理コンソール用systemd service (`scripts/linux-mcp-console.service`)
- MCP HTTP用systemd service (`scripts/linux-mcp-http.service`)
- Windows環境のサービスまたはプロセス管理
- 異なるlisten先、ログ、再起動ポリシー
- ヘルスチェックと依存順序

### 10. ネットワーク境界

- 管理コンソールは社内管理ネットワークのみ許可
- MCP HTTPは利用者ネットワークのみ許可
- AgentはMCP Serverからのみ到達可能にする
- firewall、VPN、リバースプロキシ、Network ACLを設定する
- 管理 endpointを一般利用者ネットワークへ公開しない

### 11. CSRFとブラウザセッション

**状態: CSRFの基本対策を実装済み。OIDCブラウザセッション設計が残っている。**

OIDCをブラウザログインに利用する場合は、Authorization headerだけでなくブラウザセッション設計が必要になる。

管理コンソールの変更系リクエストには同一originの `Origin` 検査を実装済み。

- OIDC Authorization Code + PKCE
- Secure / HttpOnly / SameSite cookie
- CSRF token
- logoutとsession expiry
- reverse proxyでのTLS終端位置

### 12. テスト拡張

- OIDC実JWTとJWKSの統合テスト
- admin/operator/viewerの管理操作マトリクス
- principal A/Bのserver権限分離
- Agent停止中の失効同期
- Agent復旧後の失効再送
- mTLS接続テスト
- 並行したgrant/revokeとtool実行
- SQLite migrationの既存DB互換テスト

## 実施順序

1. 本番IdPとmTLSの接続確認
2. Go Agentのビルド・テスト環境を整備
3. 承認・監査をprincipal単位に変更
4. 管理コンソールUIへprincipal管理を追加
5. Agent credentialの発行・配布・再試行を整備
6. systemd、firewall、VPN、リバースプロキシを構成
7. 統合テストとセキュリティレビューを実施

## 注意事項

- `auth_mode=oidc` では、未登録subjectを自動でprincipal化しない。
- Agentの管理失効 endpointはPrivate NetworkとmTLSで保護する。
- OIDCの署名検証を無効化した開発用fallbackを本番へ持ち込まない。
- Agent同期に失敗したcredentialを、同期済みとして表示しない。
- MCP利用者tokenとAgent接続credentialを同じ秘密として新規発行しない。
