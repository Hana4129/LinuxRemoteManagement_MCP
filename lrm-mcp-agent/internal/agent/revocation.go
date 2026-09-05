package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// revocationStore は管理失効されたトークンIDを dataDir 以下に永続化する。
//
// config.yml の hot reload や Agent 再起動でトークンマップが config から
// 再構築されても、永続化済みの失効を再適用することで「失効済みトークンの
// 復活」を防ぐ。ファイルは atomically (tmp + rename) に書き換える。
type revocationStore struct {
	path string

	mu      sync.Mutex
	revoked map[string]string // tokenID -> revokedAt (RFC3339)
}

const revocationFileName = "revocations.json"

func newRevocationStore(dataDir string) *revocationStore {
	return &revocationStore{
		path:    filepath.Join(dataDir, revocationFileName),
		revoked: make(map[string]string),
	}
}

// load はディスク上の失効記録を読み込む (存在しない場合は空のまま)。
func (r *revocationStore) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("revocations read: %w", err)
	}
	var payload struct {
		Revoked map[string]string `json:"revoked"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("revocations parse: %w", err)
	}
	revoked := make(map[string]string, len(payload.Revoked))
	for id, at := range payload.Revoked {
		if id != "" {
			revoked[id] = at
		}
	}
	r.revoked = revoked
	return nil
}

// add は失効を記録して永続化する。
func (r *revocationStore) add(tokenID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked == nil {
		r.revoked = make(map[string]string)
	}
	if _, ok := r.revoked[tokenID]; ok {
		return nil // 冪等: 既に記録済み
	}
	r.revoked[tokenID] = time.Now().UTC().Format(time.RFC3339)
	return r.persistLocked()
}

// contains は tokenID が失効済みかを返す。
func (r *revocationStore) contains(tokenID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.revoked[tokenID]
	return ok
}

// ids は失効済みトークンIDをソートして返す。
func (r *revocationStore) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.revoked))
	for id := range r.revoked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (r *revocationStore) persistLocked() error {
	payload := struct {
		Revoked map[string]string `json:"revoked"`
	}{Revoked: r.revoked}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("revocations marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("revocations mkdir: %w", err)
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("revocations write: %w", err)
	}
	if err := os.Rename(tmp, r.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("revocations rename: %w", err)
	}
	return nil
}
