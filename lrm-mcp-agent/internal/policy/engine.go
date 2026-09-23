package policy

import (
	"path"
	"strings"
)

type Scope string

const (
	ScopeReadonly Scope = "readonly"
	ScopeOperator Scope = "operator"
)

type Engine struct {
	global  GlobalPolicy
	byToken map[string]*TokenPolicy
}

type GlobalPolicy struct {
	Commands      []string
	Services      []string
	AllowedPaths  []string
	DeniedPaths   []string
	WritePaths    []string
	MaxFileSizeMB int
}

type TokenPolicy struct {
	ID       string
	Name     string
	Scope    Scope
	Commands []string
	Services []string
	Files    []string
	Disabled bool
}

func NewEngine(global GlobalPolicy) *Engine {
	return &Engine{
		global:  global,
		byToken: make(map[string]*TokenPolicy),
	}
}

func (e *Engine) AddToken(p TokenPolicy) {
	e.byToken[p.ID] = &p
}

// ListTokens は登録済み全トークンのポリシーを返す (hash等の秘密値は含まない)。
func (e *Engine) ListTokens() []*TokenPolicy {
	tokens := make([]*TokenPolicy, 0, len(e.byToken))
	for _, tp := range e.byToken {
		tokens = append(tokens, tp)
	}
	return tokens
}

func (e *Engine) GetToken(id string) *TokenPolicy {
	return e.byToken[id]
}

// cleanPath はクライアント提供パスをLinux形式 (/ 区切り) に正規化する。
// エージェントはLinux上でのみ動作するため、OS依存の filepath は使わない。
func cleanPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

func (e *Engine) CanReadFile(tokenID, path string) (bool, string) {
	tok := e.byToken[tokenID]
	if tok == nil || tok.Disabled {
		return false, "unknown or disabled token"
	}
	clean := cleanPath(path)
	for _, p := range e.global.DeniedPaths {
		if isSubpath(clean, cleanPath(p)) {
			return false, "path is denied: " + p
		}
	}
	// token-specific file allowlist takes precedence
	if len(tok.Files) > 0 {
		for _, p := range tok.Files {
			if isSubpath(clean, cleanPath(p)) {
				return true, ""
			}
		}
		return false, "path not in token allowlist"
	}
	// fall back to global allowlist
	if len(e.global.AllowedPaths) > 0 {
		for _, p := range e.global.AllowedPaths {
			if isSubpath(clean, cleanPath(p)) {
				return true, ""
			}
		}
		return false, "path not in global allowlist"
	}
	// no allowlist configured → deny by default
	return false, "no path allowlist configured"
}

// isSubpath returns true if child is a subdirectory (or the same directory) of parent.
// This prevents false positives like /var/logistics matching /var/log.
func isSubpath(child, parent string) bool {
	if child == parent {
		return true
	}
	// Ensure parent ends with / for proper prefix matching
	parentPrefix := parent
	if !strings.HasSuffix(parentPrefix, "/") {
		parentPrefix += "/"
	}
	return strings.HasPrefix(child, parentPrefix)
}

func (e *Engine) CanReadService(tokenID, service string) (bool, string) {
	tok := e.byToken[tokenID]
	if tok == nil || tok.Disabled {
		return false, "unknown or disabled token"
	}
	// 閲覧はreadonlyスコープで許可するが、対象はallowlistで絞る
	if len(tok.Services) > 0 {
		for _, s := range tok.Services {
			if s == service {
				return true, ""
			}
		}
		return false, "service not in token allowlist"
	}
	if len(e.global.Services) > 0 {
		for _, s := range e.global.Services {
			if s == service {
				return true, ""
			}
		}
		return false, "service not in global allowlist"
	}
	return false, "no service allowlist configured"
}

func (e *Engine) CanManageService(tokenID, service string) (bool, string) {
	tok := e.byToken[tokenID]
	if tok == nil || tok.Disabled {
		return false, "unknown or disabled token"
	}
	if tok.Scope != ScopeOperator {
		return false, "operator scope required"
	}
	// token-specific service allowlist
	if len(tok.Services) > 0 {
		for _, s := range tok.Services {
			if s == service {
				return true, ""
			}
		}
		return false, "service not in token allowlist"
	}
	// fall back to global allowlist
	if len(e.global.Services) > 0 {
		for _, s := range e.global.Services {
			if s == service {
				return true, ""
			}
		}
		return false, "service not in global allowlist"
	}
	return false, "no service allowlist configured"
}

func (e *Engine) CanRunCommand(tokenID, command string) (bool, string) {
	tok := e.byToken[tokenID]
	if tok == nil || tok.Disabled {
		return false, "unknown or disabled token"
	}
	if tok.Scope != ScopeOperator {
		return false, "operator scope required"
	}
	// token-specific command allowlist
	if len(tok.Commands) > 0 {
		for _, c := range tok.Commands {
			if c == command {
				return true, ""
			}
		}
		return false, "command not in token allowlist"
	}
	// fall back to global allowlist
	if len(e.global.Commands) > 0 {
		for _, c := range e.global.Commands {
			if c == command {
				return true, ""
			}
		}
		return false, "command not in global allowlist"
	}
	return false, "no command allowlist configured"
}

// CanWriteFile authorizes writing to path. Writing is destructive, so it
// requires the operator scope and an explicit write_paths allowlist
// (deny by default). Global DeniedPaths always take precedence.
func (e *Engine) CanWriteFile(tokenID, path string) (bool, string) {
	tok := e.byToken[tokenID]
	if tok == nil || tok.Disabled {
		return false, "unknown or disabled token"
	}
	if tok.Scope != ScopeOperator {
		return false, "operator scope required"
	}
	clean := cleanPath(path)
	for _, p := range e.global.DeniedPaths {
		if isSubpath(clean, cleanPath(p)) {
			return false, "path is denied: " + p
		}
	}
	if len(e.global.WritePaths) == 0 {
		return false, "no write path allowlist configured"
	}
	for _, p := range e.global.WritePaths {
		if isSubpath(clean, cleanPath(p)) {
			return true, ""
		}
	}
	return false, "path not in write allowlist"
}
