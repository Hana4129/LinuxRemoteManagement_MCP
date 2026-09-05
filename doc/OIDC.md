# OIDC設定手順書

Linux Remote Management MCP の管理コンソールを OIDC (OpenID Connect) で認証する手順を説明する。

## 1. IdP 選定基準

### 1.1 対応する IdP

以下のいずれかの IdP を利用できる。

| IdP | ライセンス | 特徴 |
|-----|-----------|------|
| Keycloak | オープンソース | セルフホスト可能、柔軟な設定 |
| Auth0 | 商用 | マネージド、簡単セットアップ |
| Okta | 商用 | エンタープライズ向け |
| Azure AD | 商用 | Microsoft 365 連携 |
| Google Identity Platform | 商用 | Google Workspace 連携 |
| Dex | オープンソース | 軽量、Kubernetes 向け |

### 1.2 必須要件

- RS256/ES256 署名アルゴリズムをサポートしていること
- JWKS (JSON Web Key Set) エンドポイントを公開していること
- `sub` (subject) クレームを発行していること
- issuer と audience を設定できること

### 1.3 選定時の確認事項

- [ ] 既存の組織ディレクトリと連携できるか
- [ ] 必要なユーザー数に対してライセンスコストが適切か
- [ ] JWKS の鍵ローテーションに対応しているか
- [ ] セッション管理・ログアウト機能を利用できるか
- [ ] 監査ログを取得できるか

## 2. 設定手順

### 2.1 IdP 側の設定

#### Keycloak の場合

1. Realm を作成する
2. Client を作成する
   - Client ID: `linux-mcp-console` (任意)
   - Client Protocol: `openid-connect`
   - Access Type: `confidential` または `public`
   - Valid Redirect URIs: ブラウザログインを利用する場合に設定
3. Client Scope で `openid` `profile` を設定
4. Issuer URL を確認: `https://keycloak.example.com/realms/{realm}`

#### Auth0 の場合

1. Application を作成 (Type: Regular Web Application)
2. Allowed Callback URLs / Logout URLs を設定
3. API で audience を設定
4. Issuer URL: `https://{tenant}.auth0.com/`

### 2.2 config.yml の設定

```yaml
console:
  auth_mode: oidc  # basic から oidc に変更
  oidc_issuer: "https://keycloak.example.com/realms/myrealm"
  oidc_audience: "linux-mcp-console"
  oidc_jwks_url: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
```

### 2.3 環境変数での設定

環境変数で設定値を上書きすることも可能。

```bash
export LINUX_MCP_OIDC_ISSUER="https://keycloak.example.com/realms/myrealm"
export LINUX_MCP_OIDC_AUDIENCE="linux-mcp-console"
export LINUX_MCP_OIDC_JWKS_URL="https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
```

## 3. Principal の事前登録

OIDC 認証時、`sub` クレームの値が事前登録された principal と一致する必要がある。

### 3.1 Principal の作成

```bash
# 管理コンソール API で principal を作成
curl -X POST http://localhost:8080/api/principals \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {admin-token}" \
  -d '{
    "subject": "oidc|user123",
    "name": "山田太郎",
    "email": "yamada@example.com",
    "roles": ["viewer"
  }'
```

### 3.2 未登録の場合の挙動

- `sub` が未登録の場合: HTTP 403 Forbidden
- 管理者が principal を作成するまでアクセス不可
- 自動登録は行わない (セキュリティポリシー)

## 4. 運用手順

### 4.1 鍵ローテーション時の挙動

IdP で鍵をローテーションした場合：

1. Agent は JWKS をキャッシュする (デフォルト 5 分)
2. ローテーション後、キャッシュ有効期限内は旧鍵で検証
3. キャッシュ期限切れ後に新鍵で再取得・検証
4. 一時的に検証に失敗した場合、キャッシュをクリアして再取得

### 4.2 JWKS 到達不能時の挙動

- JWKS URL に到達できない場合: HTTP 401 Unauthorized
- キャッシュされた鍵があれば、それで検証を継続
- キャッシュ期限が切れている場合は認証失敗

### 4.3 トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| 401 "kid not found" | JWKS に鍵がない | IdP の鍵ローテーションを確認 |
| 401 "invalid issuer" | issuer が不一致 | config.yml の oidc_issuer を確認 |
| 401 "invalid audience" | audience が不一致 | config.yml の oidc_audience を確認 |
| 403 "subject not registered" | principal 未登録 | 管理者に principal 登録を依頼 |
| 401 "token expired" | 期限切れ | IdP で新しいトークンを取得 |

## 5. リバースプロキシ設定

### 5.1 Nginx 設定例

```nginx
server {
    listen 443 ssl;
    server_name mcp-console.example.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Authorization $http_authorization;
    }
}
```

### 5.2 Apache 設定例

```apache
<VirtualHost *:443>
    ServerName mcp-console.example.com

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/cert.pem
    SSLCertificateKeyFile /etc/apache2/ssl/key.pem

    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    RequestHeader set Authorization "%{Authorization}e"
</VirtualHost>
```

### 5.3 確認事項

- [ ] `Authorization` ヘッダーが転送されているか
- [ ] `X-Forwarded-For` で正しいクライアント IP が取得できるか
- [ ] `X-Forwarded-Proto` で `https` が設定されているか
- [ ] WebSocket を利用する場合、Upgrade ヘッダーを転送するか

## 6. セキュリティ考慮事項

- OIDC トークンの署名検証は必須 (無効化しない)
- `auth_mode=oidc` と `auth_mode=basic` の fallback は本番では行わない
- JWKS URL は HTTPS のみ許可
- issuer と audience の検証を必ず有効にする
- principal の登録・失効は管理者のみが行う
- 監査ログに認証成功・失敗を記録する

## 7. ブラウザログイン (Authorization Code + PKCE)

管理コンソールをブラウザから利用する場合の OIDC ログインとセッション管理。
`oidc_browser_login: true` で有効化する (`auth_mode: oidc` が必要)。

### 7.1 config.yml の設定

```yaml
console:
  auth_required: true
  auth_mode: oidc
  oidc_issuer: https://idp.example
  oidc_audience: lrm
  oidc_jwks_url: https://idp.example/keys
  # ブラウザログイン
  oidc_browser_login: true
  oidc_client_id: lrm-console
  # confidential client の場合のみ (public client なら省略)
  # oidc_client_secret: <IdPで発行>
  oidc_redirect_uri: https://console.example/api/auth/callback
  # discovery が使えない IdP は endpoint を明示
  # oidc_authorization_endpoint: https://idp.example/authorize
  # oidc_token_endpoint: https://idp.example/token
  # リバースプロキシで TLS 終端する場合に console へは http で到達するなら false
  # session_cookie_secure: false
  session_lifetime_minutes: 480
```

IdP 側には redirect URI `https://<console>/api/auth/callback` を登録する。

### 7.2 認証フロー

1. `GET /api/auth/login` → `state` / PKCE `code_verifier` / `nonce` を生成してサーバー側に保存し、IdP の認可 URL へ 302 リダイレクト
2. ユーザーが IdP で認証 → `/api/auth/callback?code&state` へ戻る
3. サーバーは `state` を検証 (単回利用・10分TTL) して code と `code_verifier` を token endpoint へ交換 (PKCE S256)
4. `id_token` を署名・issuer・audience・`exp` 付きで検証し、`nonce` がログイン開始時と一致することを確認
5. `sub` が登録済み principal ならセッションを発行して `/` へリダイレクト (未登録は 403)

セッションはサーバー側 SQLite (`data_dir/sessions.db`) に保存され、Cookie にはランダムな
セッション ID (256bit) のみを格納する。

### 7.3 セッションと CSRF の挙動

| 項目 | 挙動 |
| --- | --- |
| セッション Cookie | `lrm_session` / HttpOnly / SameSite=Lax / Secure (既定) / 有効期限は `session_lifetime_minutes` |
| CSRF Cookie | `lrm_csrf` / JS 読み取り用 (non-HttpOnly) / SameSite=Strict |
| 変更系リクエスト | `X-CSRF-Token` ヘッダーにセッションの CSRF トークンが必要 (不一致は 403) |
| 同一 origin 検査 | Basic 認証時と同様に `Origin` ヘッダーも検査 |
| ログアウト | `POST /api/auth/logout` でセッションをサーバー側から削除し Cookie を失効 |
| 期限切れ・改竄 Cookie | 401 扱い (保護 API は未認証として拒否) |
| principal 無効化 | セッション利用中に principal が無効化されたら次リクエストで 401 となりセッション削除 |
| 権限 | セッションは principal のロールを引き継ぐ (admin のみ管理操作可) |

CSRF トークンは `/api/auth/me` の応答でも取得できる。

```bash
# ログイン状態の確認と CSRF トークン取得
curl -b cookies.txt https://console.example/api/auth/me
# 変更系 API の呼び出し
curl -b cookies.txt -H "X-CSRF-Token: <csrf_token>" -H "Content-Type: application/json" \
  -d '{"subject":"user1","display_name":"User 1","role":"viewer"}' \
  https://console.example/api/principals
```

### 7.4 リバースプロキシ構成時の注意

- TLS 終端をプロキシで行い、console へ HTTP で転送する場合は `session_cookie_secure: false` を明示する
  (Cookie の Secure 属性はブラウザが HTTPS 接続時にのみ付与されるため)。可能なら console 間も HTTPS 推奨
- プロキシで `X-Forwarded-Proto` を正しく転送しないと同一 origin 検査が失敗する場合がある
- `/api/auth/*` はプロキシで遮断しない (ログインの入口のため)

### 7.5 無効化と従来方式

`oidc_browser_login: false` (既定) の場合はブラウザログイン系エンドポイントは登録されず、
従来どおり Basic 認証または OIDC Bearer トークン (`Authorization: Bearer <id_token>`) で利用する。

