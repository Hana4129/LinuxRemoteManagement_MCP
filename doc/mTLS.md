# mTLS設定手順書

Linux Remote Management MCP で Agent との通信に mTLS (Mutual TLS) を設定する手順を説明する。

## 1. 概要

mTLS により、Agent は以下のことを保証する：
- MCP Server が正規のクライアント証明書を提示することを検証
- 証明書を持たないクライアントからの接続を拒否
- 通信経路の暗号化（TLS 1.2+）

## 2. 証明書の発行

### 2.1 CA (認証局) 証明書の作成

```bash
# CA 秘密鍵の生成
openssl genrsa -out ca.key 4096

# CA 証明書の作成（有効期間10年）
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=Linux MCP CA/O=Your Organization"
```

### 2.2 Agent サーバー証明書の作成

```bash
# Agent 秘密鍵の生成
openssl genrsa -out agent.key 2048

# 署名要求 (CSR) の作成
openssl req -new -key agent.key -out agent.csr \
  -subj "/CN=agent.example.com/O=Your Organization"

# CA による署名（SAN 含む）
openssl x509 -req -days 365 -in agent.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out agent.crt \
  -extfile <(printf "subjectAltName=DNS:agent.example.com,IP:10.0.0.1")
```

### 2.3 MCP Server クライアント証明書の作成

```bash
# クライアント秘密鍵の生成
openssl genrsa -out client.key 2048

# 署名要求 (CSR) の作成
openssl req -new -key client.key -out client.csr \
  -subj "/CN=mcp-client/O=Your Organization"

# CA による署名
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt
```

## 3. Agent 側の設定

### 3.1 config.yml の設定

```yaml
agent:
  tls:
    cert_file: /etc/linux-agent/server.crt
    key_file: /etc/linux-agent/server.key
    client_ca_file: /etc/linux-agent/ca.crt  # mTLS を有効化
```

### 3.2 ファイルの配置

```bash
# 証明書を配置
sudo mkdir -p /etc/linux-agent
sudo install -m 644 agent.crt /etc/linux-agent/server.crt
sudo install -m 600 agent.key /etc/linux-agent/server.key
sudo install -m 644 ca.crt /etc/linux-agent/ca.crt

# 専用ユーザーが読み取れるようにする
sudo chown -R linux-agent:linux-agent /etc/linux-agent
```

## 4. MCP Server 側の設定

### 4.1 config.yml の設定

```yaml
agent:
  tls_verify: true
  client_cert: /opt/linux-mcp/client.crt
  client_key: /opt/linux-mcp/client.key
```

### 4.2 ファイルの配置

```bash
sudo mkdir -p /opt/linux-mcp
sudo install -m 644 client.crt /opt/linux-mcp/client.crt
sudo install -m 600 client.key /opt/linux-mcp/client.key
sudo chown -R linux-mcp:linux-mcp /opt/linux-mcp
```

## 5. 動作確認

### 5.1 mTLS 接続の確認

```bash
# クライアント証明書ありで接続（成功するはず）
curl --cacert ca.crt --cert client.crt --key client.key \
  https://agent.example.com:8443/v1/health

# クライアント証明書なしで接続（失敗するはず）
curl --cacert ca.crt https://agent.example.com:8443/v1/health
# 期待: TLS handshake failure
```

### 5.2 証明書検証

```bash
# 証明書の内容確認
openssl x509 -in agent.crt -text -noout | grep -A2 "Subject Alternative Name"

# 証明書の有効期限確認
openssl x509 -in agent.crt -noout -dates

# CA による署名検証
openssl verify -CAfile ca.crt agent.crt
# 期待: agent.crt: OK
```

## 6. 証明書の更新

### 6.1 更新手順

1. 新しい証明書を生成
2. Agent 側の証明書を置き換え
3. Agent を再起動（または config reload）
4. 接続確認

### 6.2 ロールオーバー期間

- 新旧証明書の有効期間が重なるようにする（7日間推奨）
- CA 証明書の更新は全証明書の再発行が必要

## 7. トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| TLS handshake failed | クライアント証明書未提示 | client_cert/client_key の設定を確認 |
| certificate verify failed | CA 証明書の不一致 | client_ca_file が正しい CA か確認 |
| certificate expired | 証明書の期限切れ | 証明書を更新 |
| unknown certificate authority | 未知の CA | CA 証明書が正しく配置されているか確認 |

## 8. セキュリティ考慮事項

- CA 秘密鍵はオフラインで安全に保管する
- 証明書の有効期間は 1 年以内を推奨
- 失効した証明書は CRL または OCSP で管理する
- 証明書の更新は自動化する（cert-manager 等）
- ファイルパーミッションを適切に設定する（秘密鍵は 0600）
