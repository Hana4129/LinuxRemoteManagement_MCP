package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const adminTestHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

// adminTestConfig はコメントと未知キーを含む設定 (更新時に保持されることを検証する)。
const adminTestConfig = `# LRM Agent configuration
agent:
  name: web01-agent
  listen: ":9443"
  unknown_future_key: keep-me   # 未知キーも保持されること
  tls:
    cert_file: /etc/lrm-mcp-agent/server.crt
  tokens:
    - id: legacy
      name: legacy
      hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      scope: readonly
`

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestHashSecret_KnownVector(t *testing.T) {
	// sha256("abc")
	if got := HashSecret("abc"); got != adminTestHash {
		t.Fatalf("HashSecret(abc) = %q, want %q", got, adminTestHash)
	}
}

func TestReadSecret_TrimsTrailingNewlineOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("s3cret with space \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecret(path)
	if err != nil {
		t.Fatalf("ReadSecret: %v", err)
	}
	if got != "s3cret with space " {
		t.Fatalf("ReadSecret = %q, want %q", got, "s3cret with space ")
	}
}

func TestReadSecret_EmptyIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(path); err == nil {
		t.Fatal("ReadSecret should fail for an empty secret")
	}
}

func TestReadSecret_Stdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("from-stdin\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	got, err := ReadSecret("-")
	if err != nil {
		t.Fatalf("ReadSecret(-): %v", err)
	}
	if got != "from-stdin" {
		t.Fatalf("ReadSecret(-) = %q, want %q", got, "from-stdin")
	}
}

func TestSetAdminTokenHash_AddsKeyAndPreservesEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, adminTestConfig)

	changed, err := SetAdminTokenHash(path, adminTestHash, false)
	if err != nil {
		t.Fatalf("SetAdminTokenHash: %v", err)
	}
	if !changed {
		t.Fatal("SetAdminTokenHash should report a change")
	}

	out := readFileString(t, path)
	for _, want := range []string{
		"# LRM Agent configuration",
		"unknown_future_key: keep-me",
		"# 未知キーも保持されること",
		"admin_token_hash: " + adminTestHash,
		"id: legacy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("updated config does not contain %q:\n%s", want, out)
		}
	}
	if got := readFileString(t, path+".bak"); got != adminTestConfig {
		t.Errorf("backup content mismatch:\n%s", got)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load after update: %v", err)
	}
	if cfg.Agent.AdminTokenHash != adminTestHash {
		t.Errorf("AdminTokenHash = %q, want %q", cfg.Agent.AdminTokenHash, adminTestHash)
	}
	if len(cfg.Agent.Tokens) != 1 || cfg.Agent.Tokens[0].ID != "legacy" {
		t.Errorf("existing tokens were not preserved: %+v", cfg.Agent.Tokens)
	}
}

func TestSetAdminTokenHash_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, adminTestConfig)

	if _, err := SetAdminTokenHash(path, adminTestHash, false); err != nil {
		t.Fatalf("SetAdminTokenHash: %v", err)
	}
	first := readFileString(t, path)
	if err := os.Remove(path + ".bak"); err != nil {
		t.Fatal(err)
	}

	changed, err := SetAdminTokenHash(path, adminTestHash, false)
	if err != nil {
		t.Fatalf("second SetAdminTokenHash: %v", err)
	}
	if changed {
		t.Error("second call with the same hash should report no change")
	}
	if got := readFileString(t, path); got != first {
		t.Errorf("config was rewritten on an idempotent call:\n%s", got)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Error("no backup should be written on an idempotent call")
	}
}

func TestSetAdminTokenHash_RefusesDifferentValueWithoutReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, adminTestConfig)
	if _, err := SetAdminTokenHash(path, adminTestHash, false); err != nil {
		t.Fatalf("SetAdminTokenHash: %v", err)
	}
	before := readFileString(t, path)

	changed, err := SetAdminTokenHash(path, strings.Repeat("b", 64), false)
	if err == nil {
		t.Fatal("expected an error when the existing hash differs")
	}
	if changed {
		t.Error("changed should be false when the write is refused")
	}
	if got := readFileString(t, path); got != before {
		t.Errorf("config was modified despite the refusal:\n%s", got)
	}
	if !strings.Contains(err.Error(), "replace-admin-token") {
		t.Errorf("error message should mention -replace-admin-token: %v", err)
	}
}

func TestSetAdminTokenHash_ReplacesWithForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, adminTestConfig)
	if _, err := SetAdminTokenHash(path, adminTestHash, false); err != nil {
		t.Fatalf("SetAdminTokenHash: %v", err)
	}

	other := strings.Repeat("c", 64)
	changed, err := SetAdminTokenHash(path, other, true)
	if err != nil {
		t.Fatalf("SetAdminTokenHash(replace=true): %v", err)
	}
	if !changed {
		t.Error("replace=true should report a change")
	}
	out := readFileString(t, path)
	if !strings.Contains(out, "admin_token_hash: "+other) {
		t.Errorf("new hash not found:\n%s", out)
	}
	if strings.Contains(out, "admin_token_hash: "+adminTestHash) {
		t.Errorf("old hash still present:\n%s", out)
	}
}

func TestSetAdminTokenHash_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, "")

	changed, err := SetAdminTokenHash(path, adminTestHash, false)
	if err != nil {
		t.Fatalf("SetAdminTokenHash on empty file: %v", err)
	}
	if !changed {
		t.Error("writing into an empty config should report a change")
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.AdminTokenHash != adminTestHash {
		t.Errorf("AdminTokenHash = %q, want %q", cfg.Agent.AdminTokenHash, adminTestHash)
	}
}

func TestAppendTokenEntry_PreservesAndAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, adminTestConfig)

	entry := TokenEntry{ID: "credential-web01", Name: "web01-agent", Hash: adminTestHash, Scope: "operator"}
	if err := AppendTokenEntry(path, entry); err != nil {
		t.Fatalf("AppendTokenEntry: %v", err)
	}

	out := readFileString(t, path)
	if !strings.Contains(out, "# LRM Agent configuration") || !strings.Contains(out, "unknown_future_key: keep-me") {
		t.Errorf("comments/unknown keys were lost:\n%s", out)
	}
	if strings.Contains(out, "admin_token_hash") {
		t.Errorf("AppendTokenEntry must not touch admin_token_hash:\n%s", out)
	}
	if got := readFileString(t, path+".bak"); got != adminTestConfig {
		t.Errorf("backup content mismatch:\n%s", got)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Agent.Tokens) != 2 {
		t.Fatalf("tokens = %d, want 2", len(cfg.Agent.Tokens))
	}
	var found bool
	for _, tok := range cfg.Agent.Tokens {
		if tok.ID == "legacy" && tok.Hash != strings.Repeat("a", 64) {
			t.Errorf("existing token was modified: %+v", tok)
		}
		if tok.ID == "credential-web01" {
			found = true
			if tok.Name != "web01-agent" || tok.Hash != adminTestHash || tok.Scope != "operator" {
				t.Errorf("appended entry mismatch: %+v", tok)
			}
		}
	}
	if !found {
		t.Error("appended token not found in the reloaded config")
	}
}

func TestAppendTokenEntry_DuplicateIDIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, adminTestConfig)
	before := readFileString(t, path)

	err := AppendTokenEntry(path, TokenEntry{ID: "legacy", Name: "legacy-2", Hash: adminTestHash, Scope: "operator"})
	if err == nil {
		t.Fatal("duplicate token id should be rejected")
	}
	if !strings.Contains(err.Error(), "legacy") {
		t.Errorf("error should name the duplicate id: %v", err)
	}
	if got := readFileString(t, path); got != before {
		t.Errorf("config was modified despite the duplicate id:\n%s", got)
	}
	if _, statErr := os.Stat(path + ".bak"); !os.IsNotExist(statErr) {
		t.Error("no backup should be written when the duplicate is rejected")
	}
}

func TestAppendTokenEntry_CreatesMissingTokensSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, "agent:\n  name: minimal\n")

	if err := AppendTokenEntry(path, TokenEntry{ID: "t1", Name: "t1", Hash: adminTestHash, Scope: "readonly"}); err != nil {
		t.Fatalf("AppendTokenEntry: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Agent.Tokens) != 1 || cfg.Agent.Tokens[0].ID != "t1" {
		t.Errorf("tokens = %+v, want one entry with id t1", cfg.Agent.Tokens)
	}
	if cfg.Agent.Name != "minimal" {
		t.Errorf("existing keys were lost: name = %q", cfg.Agent.Name)
	}
}

func TestAppendTokenEntry_EmptyTokensKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	writeTestConfig(t, path, "agent:\n  name: minimal\n  tokens:\n")

	if err := AppendTokenEntry(path, TokenEntry{ID: "t2", Name: "t2", Hash: adminTestHash, Scope: "operator"}); err != nil {
		t.Fatalf("AppendTokenEntry with an empty tokens key: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Agent.Tokens) != 1 || cfg.Agent.Tokens[0].ID != "t2" {
		t.Errorf("tokens = %+v, want one entry with id t2", cfg.Agent.Tokens)
	}
}
