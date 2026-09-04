package config

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Watcher watches the config file for changes and reloads it.
// It uses mtime polling (no external dependencies).
type Watcher struct {
	path        string
	interval    time.Duration
	lastMod     time.Time
	mu          sync.Mutex
	stopCh      chan struct{}
	stopped     bool
	onReload    func(*Config)
	backupPath  string
}

// NewWatcher creates a config watcher for the given file.
// onReload is called with the newly loaded config after a successful reload.
func NewWatcher(path string, interval time.Duration, onReload func(*Config)) (*Watcher, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config file: %w", err)
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Watcher{
		path:       path,
		interval:   interval,
		lastMod:    info.ModTime(),
		stopCh:     make(chan struct{}),
		onReload:   onReload,
		backupPath: path + ".bak",
	}, nil
}

// Start begins polling the config file in a background goroutine.
func (w *Watcher) Start() {
	// 起動時の内容を初期バックアップとして保存する (最初の変更が不正でもロールバック可能にする)
	if err := w.backup(); err != nil {
		log.Printf("config watcher: initial backup failed: %v", err)
	}
	go w.loop()
}

// Stop stops the watcher.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		w.stopped = true
		close(w.stopCh)
	}
}

func (w *Watcher) loop() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.check()
		}
	}
}

func (w *Watcher) check() {
	info, err := os.Stat(w.path)
	if err != nil {
		log.Printf("config watcher: stat failed: %v", err)
		return
	}
	if !info.ModTime().After(w.lastMod) {
		return
	}
	w.lastMod = info.ModTime()
	log.Printf("config watcher: change detected in %s, reloading", w.path)

	// 新しい設定を読み込む
	cfg, err := Load(w.path)
	if err != nil {
		// 読み込み失敗時は最後に正常だった内容 (バックアップ) からロールバックする
		log.Printf("config watcher: reload failed: %v, rolling back", err)
		if rbErr := w.rollback(); rbErr != nil {
			log.Printf("config watcher: rollback failed: %v", rbErr)
		}
		if info, statErr := os.Stat(w.path); statErr == nil {
			w.lastMod = info.ModTime()
		}
		return
	}

	// ロード成功後の内容をバックアップとして保存する (常に最後に正常な内容を保持)
	if err := w.backup(); err != nil {
		log.Printf("config watcher: backup failed: %v", err)
	}

	// コールバックで Agent 側の状態 (トークン・ポリシー等) を更新する
	if w.onReload != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("config watcher: reload callback panicked: %v", r)
				}
			}()
			w.onReload(cfg)
		}()
	}
	log.Printf("config watcher: reload completed")
}

// backup copies the current config file to the backup path.
func (w *Watcher) backup() error {
	data, err := os.ReadFile(w.path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := os.WriteFile(w.backupPath, data, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	return nil
}

// rollback restores the config file from the backup.
func (w *Watcher) rollback() error {
	data, err := os.ReadFile(w.backupPath)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	if err := os.WriteFile(w.path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	log.Printf("config watcher: rolled back to previous config")
	return nil
}