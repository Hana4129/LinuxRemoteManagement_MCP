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
