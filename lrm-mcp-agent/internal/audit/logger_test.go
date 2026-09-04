package audit

import (
	"os"
	"strings"
	"testing"
)

func TestAuditLog(t *testing.T) {
	tmp, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	l, err := New(tmp.Name(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Shutdown()

	l.Log("tester", "test_action", "/test", "success", "detail", "127.0.0.1")
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "tester") {
		t.Errorf("expected actor in log: %s", s)
	}
	if !strings.Contains(s, "test_action") {
		t.Errorf("expected action in log: %s", s)
	}
}

func TestDisabled(t *testing.T) {
	l, err := New("/nonexistent/path", false)
	if err != nil {
		t.Fatal(err)
	}
	l.Log("tester", "action", "/path", "success", "", "")
}

func TestVerify_ValidChain(t *testing.T) {
	tmp, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	l, err := New(tmp.Name(), true)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		l.Log("tester", "test_action", "/test", "success", "detail", "127.0.0.1")
	}
	l.Shutdown()

	if err := Verify(tmp.Name()); err != nil {
		t.Errorf("expected valid chain, got: %v", err)
	}
}

func TestVerify_TamperedEntry(t *testing.T) {
	tmp, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	l, err := New(tmp.Name(), true)
	if err != nil {
		t.Fatal(err)
	}

	l.Log("tester", "test_action", "/test", "success", "detail", "127.0.0.1")
	l.Log("evil", "delete", "/important", "success", "", "127.0.0.1")
	l.Shutdown()

	// 2番目のエントリのアクションを改ざん
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(lines))
	}

	// 2番目のエントリのハッシュを変更（改ざん）
	lines[1] = strings.Replace(lines[1], `"action":"delete"`, `"action":"read_only"`, 1)
	tamperedData := strings.Join(lines, "\n")
	if err := os.WriteFile(tmp.Name(), []byte(tamperedData), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Verify(tmp.Name()); err == nil {
		t.Error("expected verification to fail for tampered entry, but it passed")
	}
}

func TestVerify_BrokenChain(t *testing.T) {
	tmp, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	l, err := New(tmp.Name(), true)
	if err != nil {
		t.Fatal(err)
	}

	l.Log("tester", "test_action", "/test", "success", "detail", "127.0.0.1")
	l.Log("tester", "test_action", "/test", "success", "detail", "127.0.0.1")
	l.Shutdown()

	// 最初のエントリのハッシュを空にしてチェーンを切る
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(lines))
	}

	// 2番目のエントリの prev_hash を変更してチェーンを切断
	lines[1] = strings.Replace(lines[1], `"prev_hash":"`, `"prev_hash":"deadbeefdeadbeef`, 1)
	tamperedData := strings.Join(lines, "\n")
	if err := os.WriteFile(tmp.Name(), []byte(tamperedData), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Verify(tmp.Name()); err == nil {
		t.Error("expected verification to fail for broken chain, but it passed")
	}
}

func TestRestartContinuesChain(t *testing.T) {
	tmp, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	l1, err := New(tmp.Name(), true)
	if err != nil {
		t.Fatal(err)
	}
	l1.Log("tester", "action1", "/test", "success", "detail", "127.0.0.1")
	l1.Shutdown()

	// 再起動: 新しいLoggerが前回のハッシュを復元する
	l2, err := New(tmp.Name(), true)
	if err != nil {
		t.Fatal(err)
	}
	l2.Log("tester", "action2", "/test", "success", "detail", "127.0.0.1")
	l2.Shutdown()

	if err := Verify(tmp.Name()); err != nil {
		t.Errorf("expected valid chain after restart, got: %v", err)
	}
}

