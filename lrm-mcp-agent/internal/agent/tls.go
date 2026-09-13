package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// LoadOrGenerate は証明書ファイルがあればロードし、無ければ自己署名証明書を
// 生成してファイルに書き出した上で TLS 設定を返す。
func LoadOrGenerate(certFile, keyFile string) (*tls.Config, error) {
	return LoadOrGenerateWithClientCA(certFile, keyFile, "")
}

// LoadOrGenerateWithClientCA は mTLS を有効にする (クライアント証明書の提示と検証が必須)。
// CRL による失効検証も行う場合は LoadOrGenerateWithClientCAAndCRL を使用する。
func LoadOrGenerateWithClientCA(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	return LoadOrGenerateWithClientCAAndCRL(certFile, keyFile, clientCAFile, "")
}
// LoadOrGenerateWithClientCAAndCRL は mTLS に加え、CRL (Certificate Revocation List) で
// クライアント証明書が失効していないかを検証する。
//   - crlFile は openssl ca -gencrl 相当で生成した X.509 CRL (PEM または DER) を指定する。
//   - 空文字の場合は CRL 検証をしない (従来の LoadOrGenerateWithClientCA と同等)。
//   - CRL に載っているシリアル番号のクライアント証明書は、CA検証を通過していても拒否する。
func LoadOrGenerateWithClientCAAndCRL(certFile, keyFile, clientCAFile, crlFile string) (*tls.Config, error) {
	cfg, err := loadOrGenerateBase(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if clientCAFile == "" {
		return cfg, nil
	}
	// mTLS: クライアント証明書を CA で検証する
	caData, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("failed to parse client CA certs from %s", clientCAFile)
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = caPool

	if crlFile != "" {
		crlList, err := loadRevocationList(crlFile)
		if err != nil {
			return nil, err
		}
		// CA チェーン検証済みのクライアント証明書を CRL と照合し、失効していれば拒否する。
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("client certificate verification failed")
			}
			leaf := verifiedChains[0][0]
			for _, entry := range crlList.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					return fmt.Errorf("client certificate %q is revoked (serial %s)", leaf.Subject.CommonName, leaf.SerialNumber)
				}
			}
			return nil
		}
	}
	return cfg, nil
}

// loadRevocationList は PEM または DER の X.509 CRL を読み込んで返す。
func loadRevocationList(crlFile string) (*x509.RevocationList, error) {
	data, err := os.ReadFile(crlFile)
	if err != nil {
		return nil, fmt.Errorf("read CRL: %w", err)
	}
	// PEM 形式 (openssl ca -gencrl の出力) は DER にデコードする。
	if block, _ := pem.Decode(data); block != nil && block.Type == "X509 CRL" {
		data = block.Bytes
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parse CRL %s: %w", crlFile, err)
	}
	return crl, nil
}

// loadOrGenerateBase は証明書ファイルがあればロードし、無ければ自己署名証明書を生成する。
func loadOrGenerateBase(certFile, keyFile string) (*tls.Config, error) {
	if fileExists(certFile) && fileExists(keyFile) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		return tlsConfigWithCert(cert), nil
	}
	return generateSelfSigned(certFile, keyFile)
}

func tlsConfigWithCert(cert tls.Certificate) *tls.Config {
	// CipherSuites は TLS 1.2 以下にのみ適用される (TLS 1.3 のスイートは常に有効)。
	// HTTP/2 は ECDHE + AEAD (GCM/CHACHA20) の TLS 1.2 スイートを必須とするため、
	// その条件を満たすスイートのみに限定する (CBC など非AEADは排除)。
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func generateSelfSigned(certFile, keyFile string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lrm-mcp-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	certOut, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open cert: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		return nil, fmt.Errorf("encode cert: %w", err)
	}
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyOut, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		keyOut.Close()
		return nil, fmt.Errorf("encode key: %w", err)
	}
	keyOut.Close()
	return tlsConfigWithCert(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}), nil
}
