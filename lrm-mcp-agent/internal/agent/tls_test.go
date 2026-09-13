package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCA writes a self-signed CA certificate (PEM) to path and returns the path.
func writeTestCA(t *testing.T, dir string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadOrGenerate_NoClientCA(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	cfg, err := LoadOrGenerate(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert when client CA not set, got %v", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 minimum, got %v", cfg.MinVersion)
	}
}

func TestLoadOrGenerateWithClientCA_EnablesMTLS(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	caFile := writeTestCA(t, dir)

	cfg, err := LoadOrGenerateWithClientCA(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("LoadOrGenerateWithClientCA failed: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert for mTLS, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("expected ClientCAs pool to be set for mTLS")
	}
}

func TestLoadOrGenerateWithClientCA_InvalidCA(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	badCA := filepath.Join(dir, "bad-ca.crt")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadOrGenerateWithClientCA(certFile, keyFile, badCA)
	if err == nil {
		t.Error("expected error for invalid client CA")
	}
}

func TestLoadOrGenerateWithClientCA_MissingCA(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	_, err := LoadOrGenerateWithClientCA(certFile, keyFile, filepath.Join(dir, "nope.crt"))
	if err == nil {
		t.Error("expected error for missing client CA file")
	}
}

// writeTestCAWithKey はクライアント証明書の発行に使える CA (証明書+秘密鍵) を作成する。
func writeTestCAWithKey(t *testing.T, dir, name string) (caFile string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+"-ca.crt")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cert, priv
}

// issueClientCert はCAで署名したクライアント証明書 (cert/key PEMファイル) を作成する。
func issueClientCert(t *testing.T, dir string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, name string) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 同一 nano-second での生成衝突を避けるため crypto/rand でシリアルを生成する
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestMTLSHandshake_ClientCertificateEnforcement は実際のTLSハンドシェイクで
// mTLS有効時に証明書なし・不正証明書が拒否され、正当な証明書のみ許可されることを検証する。
func TestMTLSHandshake_ClientCertificateEnforcement(t *testing.T) {
	dir := t.TempDir()
	caFile, caCert, caKey := writeTestCAWithKey(t, dir, "client-ca")
	_, rogueCert, rogueKey := writeTestCAWithKey(t, dir, "rogue-ca")
	validCert, validKey := issueClientCert(t, dir, caCert, caKey, "valid-client")
	rogueClientCert, rogueClientKey := issueClientCert(t, dir, rogueCert, rogueKey, "rogue-client")
	_ = rogueClientKey

	serverCert := filepath.Join(dir, "server.crt")
	serverKey := filepath.Join(dir, "server.key")
	cfg, err := LoadOrGenerateWithClientCA(serverCert, serverKey, caFile)
	if err != nil {
		t.Fatalf("LoadOrGenerateWithClientCA failed: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(srv.Certificate())

	newClient := func(certFile, keyFile string) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12}}
		if certFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
		return &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}

	// 証明書なし → ハンドシェイク拒否
	if _, err := newClient("", "").Get(srv.URL); err == nil {
		t.Error("expected TLS handshake failure without client certificate")
	}

	// 不正なクライアント証明書 (未知のCA署名) → ハンドシェイク拒否
	if _, err := newClient(rogueClientCert, rogueClientKey).Get(srv.URL); err == nil {
		t.Error("expected TLS handshake failure with rogue client certificate")
	}

	// 正当なクライアント証明書 → 200
	resp, err := newClient(validCert, validKey).Get(srv.URL)
	if err != nil {
		t.Fatalf("expected handshake to succeed with valid client certificate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with valid client certificate, got %d", resp.StatusCode)
	}
}
// serialOf は PEM 形式の証明書ファイルからシリアル番号を返すテストヘルパー。
func serialOf(t *testing.T, certFile string) *big.Int {
	t.Helper()
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert.SerialNumber
}

// TestMTLSHandshake_CRLRevocation は CRL に載ったクライアント証明書だけが
// ハンドシェイクで拒否され、CRL に載っていない証明書は許可されることを検証する。
func TestMTLSHandshake_CRLRevocation(t *testing.T) {
	dir := t.TempDir()
	caFile, caCert, caKey := writeTestCAWithKey(t, dir, "client-ca")
	validCert, validKey := issueClientCert(t, dir, caCert, caKey, "valid-client")
	revokedCert, revokedKey := issueClientCert(t, dir, caCert, caKey, "revoked-client")

	// 失効対象: revoked-client のシリアルだけを CRL に載せる
	revokedSerial := serialOf(t, revokedCert)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now()},
		},
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList failed: %v", err)
	}
	crlFile := filepath.Join(dir, "client-ca.crl")
	if err := os.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	serverCert := filepath.Join(dir, "server.crt")
	serverKey := filepath.Join(dir, "server.key")
	cfg, err := LoadOrGenerateWithClientCAAndCRL(serverCert, serverKey, caFile, crlFile)
	if err != nil {
		t.Fatalf("LoadOrGenerateWithClientCAAndCRL failed: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(srv.Certificate())

	newClient := func(certFile, keyFile string) *http.Client {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		}
		return &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}

	// CRL に載った revoked-client → 拒否 (TLS alert: bad certificate)
	// ※ クライアント側には "revoked" 等の詳細は届かない (alert のみ)。詳細はサーバー側で拒否になる。
	if _, err := newClient(revokedCert, revokedKey).Get(srv.URL); err == nil {
		t.Error("expected TLS handshake failure for revoked client certificate")
	}

	// CRL に載っていない valid-client → 200
	resp, err := newClient(validCert, validKey).Get(srv.URL)
	if err != nil {
		t.Fatalf("expected handshake to succeed with non-revoked client certificate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with valid client certificate, got %d", resp.StatusCode)
	}
}

// TestMTLSHandshake_CRLDisabled は CRL を指定しない場合に従来同様
// 同一CA署名のクライアント証明書が許可されることを検証する。
func TestMTLSHandshake_CRLDisabled(t *testing.T) {
	dir := t.TempDir()
	caFile, caCert, caKey := writeTestCAWithKey(t, dir, "client-ca")
	certA, keyA := issueClientCert(t, dir, caCert, caKey, "client-a")

	serverCert := filepath.Join(dir, "server.crt")
	serverKey := filepath.Join(dir, "server.key")
	cfg, err := LoadOrGenerateWithClientCAAndCRL(serverCert, serverKey, caFile, "")
	if err != nil {
		t.Fatalf("LoadOrGenerateWithClientCAAndCRL (no CRL) failed: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(srv.Certificate())

	cert, err := tls.LoadX509KeyPair(certA, keyA)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected handshake to succeed without CRL: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 without CRL, got %d", resp.StatusCode)
	}
}