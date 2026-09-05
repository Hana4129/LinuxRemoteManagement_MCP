package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/internal/lrm-mcp-agent/internal/config"
)

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func newTestAgent() *Agent {
	cfg := &config.Config{
		Agent: config.AgentConfig{
			Name:    "test-agent",
			Listen:  ":8443",
			DataDir: "./data",
			Env:     "test",
			AdminTokenHash: hashToken("admin-secret"),
			TLS: config.TLSConfig{
				AutoCertFile: "./data/server.crt",
				AutoKeyFile:  "./data/server.key",
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
				LogFile: "./data/audit.log",
			},
		},
	}

	agent, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return agent
}

func TestAuthenticate_ValidToken(t *testing.T) {
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
	defer agent.Shutdown()

	if agent.engine == nil {
		t.Error("expected policy engine to be initialized")
	}

	if len(agent.tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(agent.tokens))
	}
}

func TestAuthenticate_NoToken(t *testing.T) {
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
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
	agent := newTestAgent()
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/v1/health", nil)

	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for health check, got %d", rr.Code)
	}
}
