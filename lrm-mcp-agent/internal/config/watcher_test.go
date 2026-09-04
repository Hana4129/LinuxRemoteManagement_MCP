package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeTestConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWatcher_ReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	writeTestConfig(t, cfgPath, "agent:\n  name: agent-a\n  listen: \":8443\"\n")

	var mu sync.Mutex
	reloaded := 0
	var gotName string

	w, err := NewWatcher(cfgPath, 50*time.Millisecond, func(cfg *Config) {
		mu.Lock()
		reloaded++
		gotName = cfg.Agent.Name
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Stop()

	// 設定を変更する (mtime が確実に進むよう少し待つ)
	time.Sleep(100 * time.Millisecond)
	writeTestConfig(t, cfgPath, "agent:\n  name: agent-b\n  listen: \":8443\"\n")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		r, n := reloaded, gotName
		mu.Unlock()
		if r > 0 {
			if n != "agent-b" {
				t.Errorf("expected reloaded name 'agent-b', got %q", n)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("reload was not triggered within deadline")
}

func TestWatcher_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	writeTestConfig(t, cfgPath, "agent:\n  name: original\n")

	w, err := NewWatcher(cfgPath, 50*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Stop()

	time.Sleep(100 * time.Millisecond)
	writeTestConfig(t, cfgPath, "agent:\n  name: updated\n")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(w.backupPath); err == nil {
			return // backup created
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("backup file was not created within deadline")
}

func TestWatcher_RollbackOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	writeTestConfig(t, cfgPath, "agent:\n  name: valid\n")

	var mu sync.Mutex
	reloaded := 0
	w, err := NewWatcher(cfgPath, 50*time.Millisecond, func(cfg *Config) {
		mu.Lock()
		reloaded++
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Stop()

	time.Sleep(100 * time.Millisecond)
	// 無効な YAML を書き込む
	writeTestConfig(t, cfgPath, "agent: [invalid: yaml\n")

	// リロード試行後、バックアップからロールバックされ元の内容に戻ることを確認
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(cfgPath)
		if err == nil && len(data) > 0 {
			// ロールバックで元の内容が復元されていればパースできる
			if _, err := Load(cfgPath); err == nil {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = mu // avoid unused variable in some code paths
	t.Log("reload attempts:", reloaded)
	t.Fatal("config was not rolled back to a valid state within deadline")
}

func TestWatcher_Stop(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	writeTestConfig(t, cfgPath, "agent:\n  name: x\n")

	w, err := NewWatcher(cfgPath, 50*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	w.Stop()
	// Stop を 2 回呼んでも panic しないこと
	w.Stop()
}
