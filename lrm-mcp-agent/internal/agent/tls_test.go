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