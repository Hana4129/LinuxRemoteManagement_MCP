package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/internal/lrm-mcp-agent/internal/config"
)

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func newTestConfig(dataDir string) *config.Config {
	cfg := &config.Config{
		Agent: config.AgentConfig{
			Name:    "test-agent",
			Listen:  ":8443",
			DataDir: dataDir,
			Env:     "test",
			AdminTokenHash: hashToken("admin-secret"),
			TLS: config.TLSConfig{
				AutoCertFile: dataDir + "/server.crt",
				AutoKeyFile:  dataDir + "/server.key",
			},
			Tokens: []config.TokenEntry{
				{
					ID:    "ro-token",
					Name:  "readonly",
					Hash:  hashToken("ro-secret"),
					Scope: "readonly",
				},
				{
					ID:    "op-token",
					Name:  "operator",
					Hash:  hashToken("op-secret"),
					Scope: "operator",
					Commands: []string{
						"systemctl restart nginx",
					},
					Services: []string{
						"nginx",
					},
				},
			},
			Allowlist: config.Allowlist{
				Commands: []string{
					"systemctl restart nginx",
				},
				Services: []string{
					"nginx",
				},
				AllowedPaths: []string{
					"/etc/",
				},
				DeniedPaths: []string{
					"/etc/shadow",
				},
				MaxFileSizeMB: 10,
			},
			RateLimit: config.RateLimit{
				Enabled:   true,
				PerMinute: 60,
				Burst:     10,
			},
			Audit: config.AuditConfig{
				Enabled:  false,
				LogFile:  dataDir + "/audit.log",
			},
		},
	}

	return cfg
}

func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	return newTestAgentInDir(t.TempDir())
}

// newTestAgentInDir は指定ディレクトリへ失効記録を書くテスト用エージェントを生成する。
func newTestAgentInDir(dataDir string) *Agent {
	agent, err := New(newTestConfig(dataDir))
	if err != nil {
		panic(err)
	}
	return agent
}

// revokeTokenViaAPI は管理endpoint経由でトークンを失効させる。
func revokeTokenViaAPI(t *testing.T, handler http.Handler, tokenID string) {
	t.Helper()
	revoke := httptest.NewRequest("POST", "/v1/admin/tokens/"+tokenID+"/revoke", nil)
	revoke.Header.Set("X-LRM-Admin-Token", "admin-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, revoke)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected admin revoke to succeed, got %d", rr.Code)
	}
}

// requestWithToken はBearerトークン付きリクエストのステータスコードを返す。
func requestWithToken(handler http.Handler, token string) int {
	req := httptest.NewRequest("GET", "/v1/system", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code
}

func TestAuthenticate_ValidToken(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/system", nil)
	req.Header.Set("Authorization", "Bearer ro-secret")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized {
		t.Errorf("expected authenticated request to succeed, got %d", rr.Code)
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/system", nil)
	req.Header.Set("Authorization", "Bearer invalid-secret")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", rr.Code)
	}
}

func TestHandleSystem_Readonly(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/system", nil)
	req.Header.Set("Authorization", "Bearer ro-secret")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for readonly access, got %d", rr.Code)
	}
}

func TestHandleDisk_Readonly(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/disk", nil)
	req.Header.Set("Authorization", "Bearer ro-secret")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for readonly access, got %d", rr.Code)
	}
}

func TestHandleProcesses_Readonly(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/processes", nil)
	req.Header.Set("Authorization", "Bearer ro-secret")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for readonly access, got %d", rr.Code)
	}
}

func TestHandleServices_Readonly(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/services/nginx", nil)
	req.Header.Set("Authorization", "Bearer ro-secret")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for readonly access, got %d", rr.Code)
	}
}

func TestHandleExecute_OperatorOnly(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("POST", "/v1/execute", strings.NewReader(`{"command":"systemctl restart nginx"}`))
	req.Header.Set("Authorization", "Bearer ro-secret")
	req.Header.Set("Content-Type", "application/json")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for readonly token, got %d", rr.Code)
	}
}

func TestHandleRestart_OperatorOnly(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("POST", "/v1/services/nginx/restart", nil)
	req.Header.Set("Authorization", "Bearer ro-secret")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for readonly token, got %d", rr.Code)
	}
}

func TestPolicyEngine_Integration(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	if agent.engine == nil {
		t.Error("expected policy engine to be initialized")
	}

	if len(agent.tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(agent.tokens))
	}
}

func TestAuthenticate_NoToken(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/system", nil)

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no token, got %d", rr.Code)
	}
}

func TestAuthenticate_WrongFormat(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/system", nil)
	req.Header.Set("Authorization", "Basic wrongformat")

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong auth format, got %d", rr.Code)
	}
}

func TestAdminTokenRevoke_DisablesTokenImmediately(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()
	handler := agent.Handler()

	revoke := httptest.NewRequest("POST", "/v1/admin/tokens/ro-token/revoke", nil)
	revoke.Header.Set("X-LRM-Admin-Token", "admin-secret")
	revokeResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokeResponse, revoke)
	if revokeResponse.Code != http.StatusOK {
		t.Fatalf("expected admin revoke to succeed, got %d", revokeResponse.Code)
	}

	request := httptest.NewRequest("GET", "/v1/system", nil)
	request.Header.Set("Authorization", "Bearer ro-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Errorf("expected revoked token to receive 401, got %d", response.Code)
	}
}

func TestAdminTokenRevoke_InvalidSecret(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()
	revoke := httptest.NewRequest("POST", "/v1/admin/tokens/ro-token/revoke", nil)
	revoke.Header.Set("X-LRM-Admin-Token", "wrong-secret")
	response := httptest.NewRecorder()
	agent.Handler().ServeHTTP(response, revoke)
	if response.Code != http.StatusUnauthorized {
		t.Errorf("expected invalid admin secret to receive 401, got %d", response.Code)
	}
}

func TestHandleHealth_NoAuth(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/health", nil)

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for health check, got %d", rr.Code)
	}
}

func TestRevocationSurvivesConfigReload(t *testing.T) {
	dir := t.TempDir()
	agent := newTestAgentInDir(dir)
	defer agent.Shutdown()
	handler := agent.Handler()

	revokeTokenViaAPI(t, handler, "ro-token")

	// config 上は ro-token が有効のまま reload (hot reload相当)
	agent.Reload(newTestConfig(dir))

	// reload後も失効済みトークンは401のまま (復活しない)
	if code := requestWithToken(agent.Handler(), "ro-secret"); code != http.StatusUnauthorized {
		t.Errorf("expected revoked token to stay unauthorized after reload, got %d", code)
	}
	// 他のトークンは影響を受けない
	if code := requestWithToken(agent.Handler(), "op-secret"); code == http.StatusUnauthorized {
		t.Errorf("expected non-revoked token to remain authenticated after reload, got %d", code)
	}
}

func TestRevocationPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	first := newTestAgentInDir(dir)
	revokeTokenViaAPI(t, first.Handler(), "ro-token")
	first.Shutdown()

	// 同じ dataDir で再起動相当: config 上は ro-token 有効
	second := newTestAgentInDir(dir)
	defer second.Shutdown()

	if code := requestWithToken(second.Handler(), "ro-secret"); code != http.StatusUnauthorized {
		t.Errorf("expected revoked token to stay unauthorized after restart, got %d", code)
	}
	if code := requestWithToken(second.Handler(), "op-secret"); code == http.StatusUnauthorized {
		t.Errorf("expected non-revoked token to remain authenticated after restart, got %d", code)
	}
}

func TestRevocationStoreWritesFile(t *testing.T) {
	dir := t.TempDir()
	agent := newTestAgentInDir(dir)
	defer agent.Shutdown()

	revokeTokenViaAPI(t, agent.Handler(), "ro-token")
	// 冪等性: 同じトークンの重複失効も成功する
	revokeTokenViaAPI(t, agent.Handler(), "ro-token")

	data, err := os.ReadFile(filepath.Join(dir, "revocations.json"))
	if err != nil {
		t.Fatalf("expected revocations.json to be written: %v", err)
	}
	if !strings.Contains(string(data), "ro-token") {
		t.Errorf("expected revocations.json to contain ro-token, got: %s", data)
	}
	if filepath.Base(dir) == "" || len(agent.revocations.ids()) != 1 {
		t.Errorf("expected exactly 1 revoked token id, got %v", agent.revocations.ids())
	}
}
