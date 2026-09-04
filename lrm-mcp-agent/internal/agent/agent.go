package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/internal/lrm-mcp-agent/internal/audit"
	"github.com/internal/lrm-mcp-agent/internal/config"
	"github.com/internal/lrm-mcp-agent/internal/policy"
)

type Agent struct {
	cfg         *config.Config
	engine      *policy.Engine
	auditLog    *audit.Logger
	tokens      map[string]tokenEntry
	rateLimiter *rateLimiter
	mu          sync.RWMutex
}

type tokenEntry struct {
	id    string
	name  string
	hash  string
	scope policy.Scope
	policy.TokenPolicy
}

func New(cfg *config.Config) (*Agent, error) {
	siemConfig := audit.SIEMConfig{
		Enabled:    cfg.Agent.Audit.SIEM.Enabled,
		WebhookURL: cfg.Agent.Audit.SIEM.WebhookURL,
		APIKey:     cfg.Agent.Audit.SIEM.APIKey,
		Format:     cfg.Agent.Audit.SIEM.Format,
	}
	auditLog, err := audit.NewWithFullConfig(cfg.Agent.Audit.LogFile, cfg.Agent.Audit.Enabled, audit.DefaultRotationConfig(), siemConfig)
	if err != nil {
		return nil, err
	}
	global := policy.GlobalPolicy{
		Commands:      cfg.Agent.Allowlist.Commands,
		Services:      cfg.Agent.Allowlist.Services,
		AllowedPaths:  cfg.Agent.Allowlist.AllowedPaths,
		DeniedPaths:   cfg.Agent.Allowlist.DeniedPaths,
		WritePaths:    cfg.Agent.Allowlist.WritePaths,
		MaxFileSizeMB: cfg.Agent.Allowlist.MaxFileSizeMB,
	}
	engine := policy.NewEngine(global)
	a := &Agent{
		cfg:         cfg,
		engine:      engine,
		auditLog:    auditLog,
		tokens:      make(map[string]tokenEntry),
		rateLimiter: newRateLimiter(cfg.Agent.RateLimit.PerMinute, cfg.Agent.RateLimit.Burst),
	}
	for _, t := range cfg.Agent.Tokens {
		a.addToken(t)
	}
	return a, nil
}

func (a *Agent) addToken(t config.TokenEntry) {
	var scope policy.Scope
	if t.Scope == "operator" {
		scope = policy.ScopeOperator
	} else {
		scope = policy.ScopeReadonly
	}
	a.tokens[t.ID] = tokenEntry{
		id:    t.ID,
		name:  t.Name,
		hash:  t.Hash,
		scope: scope,
		TokenPolicy: policy.TokenPolicy{
			ID:       t.ID,
			Name:     t.Name,
			Scope:    scope,
			Commands: t.Commands,
			Services: t.Services,
			Files:    t.Files,
			Disabled: t.Disabled,
		},
	}
	a.engine.AddToken(policy.TokenPolicy{
		ID:       t.ID,
		Name:     t.Name,
		Scope:    scope,
		Commands: t.Commands,
		Services: t.Services,
		Files:    t.Files,
		Disabled: t.Disabled,
	})
}

func (a *Agent) Shutdown() {
	if a.auditLog != nil {
		a.auditLog.Shutdown()
	}
}

// Reload replaces the token and policy state from the given config.
// The server keeps running; only tokens/allowlists are swapped atomically.
func (a *Agent) Reload(cfg *config.Config) {
	global := policy.GlobalPolicy{
		Commands:      cfg.Agent.Allowlist.Commands,
		Services:      cfg.Agent.Allowlist.Services,
		AllowedPaths:  cfg.Agent.Allowlist.AllowedPaths,
		DeniedPaths:   cfg.Agent.Allowlist.DeniedPaths,
		WritePaths:    cfg.Agent.Allowlist.WritePaths,
		MaxFileSizeMB: cfg.Agent.Allowlist.MaxFileSizeMB,
	}
	engine := policy.NewEngine(global)
	tokens := make(map[string]tokenEntry)

	a.mu.Lock()
	defer a.mu.Unlock()

	// 認可判定は新しい Engine に対して行う (新旧トークン混在を防ぐ)
	for _, t := range cfg.Agent.Tokens {
		var scope policy.Scope
		if t.Scope == "operator" {
			scope = policy.ScopeOperator
		} else {
			scope = policy.ScopeReadonly
		}
		tp := policy.TokenPolicy{
			ID:       t.ID,
			Name:     t.Name,
			Scope:    scope,
			Commands: t.Commands,
			Services: t.Services,
			Files:    t.Files,
			Disabled: t.Disabled,
		}
		engine.AddToken(tp)
		tokens[t.ID] = tokenEntry{
			id:          t.ID,
			name:        t.Name,
			hash:        t.Hash,
			scope:       scope,
			TokenPolicy: tp,
		}
	}

	a.engine = engine
	a.tokens = tokens
	a.auditLog.Log("system", "config_reload", cfg.Agent.Name, "ok", "", "")
	log.Printf("agent reloaded: %d tokens active", len(tokens))
}

func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", a.handleHealth)
	mux.HandleFunc("/v1/system", a.handleSystem)
	mux.HandleFunc("/v1/disk", a.handleDisk)
	mux.HandleFunc("/v1/processes", a.handleProcesses)
	mux.HandleFunc("/v1/services/", a.handleServices)
	mux.HandleFunc("/v1/files", a.handleFiles)
	mux.HandleFunc("/v1/execute", a.handleExecute)
	mux.HandleFunc("/metrics", handleMetrics)
	return a.middlewareStack(mux)
}
func (a *Agent) middlewareStack(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		IncrementRequests()
		if r.URL.Path == "/metrics" || r.URL.Path == "/v1/health" {
			h.ServeHTTP(w, r)
			return
		}
		if a.cfg.Agent.RateLimit.Enabled {
			ip := clientIP(r)
			if !a.rateLimiter.allow(ip) {
				IncrementRateLimitHits()
				a.auditLog.Log("anonymous", "rate_limit", r.URL.Path, "denied", "", ip)
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
				return
			}
		}
		token, ok := a.authenticate(r)
		if !ok {
			IncrementAuthFailures()
			a.auditLog.Log("anonymous", "auth", r.URL.Path, "unauthorized", "", clientIP(r))
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		IncrementAuthSuccess()
		ctx := withToken(r.Context(), token)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Agent) authenticate(r *http.Request) (*tokenEntry, bool) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return nil, false
	}
	raw := strings.TrimPrefix(hdr, "Bearer ")
	hash := sha256.Sum256([]byte(raw))
	hashStr := hex.EncodeToString(hash[:])
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, t := range a.tokens {
		if subtle.ConstantTimeCompare([]byte(t.hash), []byte(hashStr)) == 1 {
			return &t, true
		}
	}
	return nil, false
}

func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"agent_version": "0.1.0",
		"hostname":      a.cfg.Agent.Name,
	})
}

func (a *Agent) handleSystem(w http.ResponseWriter, r *http.Request) {
	info := getSystemInfo()
	writeJSON(w, http.StatusOK, info)
}

func (a *Agent) handleDisk(w http.ResponseWriter, r *http.Request) {
	disks := getDiskUsage()
	writeJSON(w, http.StatusOK, map[string]interface{}{"filesystems": disks})
}

func (a *Agent) handleProcesses(w http.ResponseWriter, r *http.Request) {
	procs := getProcesses()
	writeJSON(w, http.StatusOK, map[string]interface{}{"processes": procs})
}

func (a *Agent) handleServices(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/services/")
	if path == "" || path == "logs" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "service name required"})
		return
	}
	if strings.HasSuffix(path, "/logs") {
		svc := strings.TrimSuffix(path, "/logs")
		a.handleServiceLogs(w, r, svc)
		return
	}
	if strings.HasSuffix(path, "/restart") {
		svc := strings.TrimSuffix(path, "/restart")
		a.handleServiceRestart(w, r, svc)
		return
	}
	a.handleServiceStatus(w, r, path)
}

func (a *Agent) handleServiceStatus(w http.ResponseWriter, r *http.Request, service string) {
	ok, reason := a.engine.CanReadService(currentToken(r).id, service)
	if !ok {
		a.auditLog.Log(currentToken(r).id, "service_status", service, "denied", reason, clientIP(r))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}
	status := getServiceStatus(service)
	a.auditLog.Log(currentToken(r).id, "service_status", service, "ok", "", clientIP(r))
	writeJSON(w, http.StatusOK, status)
}

func (a *Agent) handleServiceRestart(w http.ResponseWriter, r *http.Request, service string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	ok, reason := a.engine.CanManageService(currentToken(r).id, service)
	if !ok {
		a.auditLog.Log(currentToken(r).id, "service_restart", service, "denied", reason, clientIP(r))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}
	result := restartService(service)
	a.auditLog.Log(currentToken(r).id, "service_restart", service, "ok", "", clientIP(r))
	writeJSON(w, http.StatusOK, result)
}

func (a *Agent) handleServiceLogs(w http.ResponseWriter, r *http.Request, service string) {
	ok, reason := a.engine.CanReadService(currentToken(r).id, service)
	if !ok {
		a.auditLog.Log(currentToken(r).id, "service_logs", service, "denied", reason, clientIP(r))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}
	logs := getServiceLogs(service)
	a.auditLog.Log(currentToken(r).id, "service_logs", service, "ok", "", clientIP(r))
	writeJSON(w, http.StatusOK, logs)
}

func (a *Agent) handleFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path required"})
		return
	}
	if r.Method == http.MethodPost {
		a.handleFileWrite(w, r, path)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
		return
	}
	ok, reason := a.engine.CanReadFile(currentToken(r).id, path)
	if !ok {
		a.auditLog.Log(currentToken(r).id, "read_file", path, "denied", reason, clientIP(r))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}
	content, err := readFile(path, a.cfg.Agent.Allowlist.MaxFileSizeMB)
	if err != nil {
		a.auditLog.Log(currentToken(r).id, "read_file", path, "error", err.Error(), clientIP(r))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.auditLog.Log(currentToken(r).id, "read_file", path, "ok", "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"path": path, "content": content})
}

// handleFileWrite writes content to path (POST /v1/files?path=...).
// Writing is destructive: operator scope + write_paths allowlist required.
func (a *Agent) handleFileWrite(w http.ResponseWriter, r *http.Request, path string) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	ok, reason := a.engine.CanWriteFile(currentToken(r).id, path)
	if !ok {
		a.auditLog.Log(currentToken(r).id, "write_file", path, "denied", reason, clientIP(r))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}
	backup, err := writeFile(path, req.Content, a.cfg.Agent.Allowlist.MaxFileSizeMB)
	if err != nil {
		a.auditLog.Log(currentToken(r).id, "write_file", path, "error", err.Error(), clientIP(r))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.auditLog.Log(currentToken(r).id, "write_file", path, "ok", "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"path": path, "backup": backup, "status": "written"})
}

func (a *Agent) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	ok, reason := a.engine.CanRunCommand(currentToken(r).id, req.Command)
	if !ok {
		a.auditLog.Log(currentToken(r).id, "execute", req.Command, "denied", reason, clientIP(r))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	}
	timeout := time.Duration(a.cfg.Agent.Execution.CommandTimeoutSeconds) * time.Second
	result := executeCommandWithTimeout(req.Command, timeout)
	logResult := "ok"
	detail := ""
	if result.TimedOut {
		logResult = "timeout"
	} else if strings.Contains(result.Stderr, "forbidden shell metacharacter") ||
		strings.Contains(result.Stderr, "subshell substitution") {
		logResult = "rejected"
		detail = result.Stderr
	}
	a.auditLog.Log(currentToken(r).id, "execute", req.Command, logResult, detail, clientIP(r))
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	if status >= 400 {
		IncrementErrors()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return strings.Split(xff, ",")[0]
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	if host == "" {
		return r.RemoteAddr
	}
	return host
}

func currentToken(r *http.Request) *tokenEntry {
	return r.Context().Value(tokenKey).(*tokenEntry)
}

type contextKey string

const tokenKey contextKey = "token"

func withToken(ctx context.Context, t *tokenEntry) context.Context {
	return context.WithValue(ctx, tokenKey, t)
}
