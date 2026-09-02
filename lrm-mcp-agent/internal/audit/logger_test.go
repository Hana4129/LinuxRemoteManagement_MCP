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
