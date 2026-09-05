package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMetricsEndpoint_NoAuth(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("GET", "/metrics", nil)
	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for metrics endpoint, got %d", rr.Code)
	}
}

func TestMetricsEndpoint_PrometheusFormat(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	// Generate some metrics
	IncrementRequests()
	IncrementAuthSuccess()
	IncrementAuthFailures()

	req := httptest.NewRequest("GET", "/metrics", nil)
	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	expectedMetrics := []string{
		"lrm_agent_requests_total",
		"lrm_agent_requests_errors_total",
		"lrm_agent_auth_success_total",
		"lrm_agent_auth_failures_total",
		"lrm_agent_rate_limit_hits_total",
		"lrm_agent_uptime_seconds",
		"lrm_agent_memory_bytes",
		"lrm_agent_cpu_goroutines",
	}
	for _, m := range expectedMetrics {
		if !strings.Contains(body, m) {
			t.Errorf("expected metrics output to contain %q", m)
		}
	}
}

func TestMetricsEndpoint_MethodNotAllowed(t *testing.T) {
	agent := newTestAgent(t)
	defer agent.Shutdown()

	req := httptest.NewRequest("POST", "/metrics", nil)
	handler := agent.Handler()
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST to metrics, got %d", rr.Code)
	}
}

func TestMetricsCounters(t *testing.T) {
	before := atomic.LoadInt64(&metrics.requestsTotal)
	IncrementRequests()
	after := atomic.LoadInt64(&metrics.requestsTotal)
	if after != before+1 {
		t.Errorf("expected requests counter to increment by 1, got %d -> %d", before, after)
	}

	before = atomic.LoadInt64(&metrics.authSuccess)
	IncrementAuthSuccess()
	after = atomic.LoadInt64(&metrics.authSuccess)
	if after != before+1 {
		t.Errorf("expected auth success counter to increment by 1, got %d -> %d", before, after)
	}

	before = atomic.LoadInt64(&metrics.authFailures)
	IncrementAuthFailures()
	after = atomic.LoadInt64(&metrics.authFailures)
	if after != before+1 {
		t.Errorf("expected auth failure counter to increment by 1, got %d -> %d", before, after)
	}

	before = atomic.LoadInt64(&metrics.rateLimitHits)
	IncrementRateLimitHits()
	after = atomic.LoadInt64(&metrics.rateLimitHits)
	if after != before+1 {
		t.Errorf("expected rate limit counter to increment by 1, got %d -> %d", before, after)
	}

	before = atomic.LoadInt64(&metrics.requestsErrors)
	IncrementErrors()
	after = atomic.LoadInt64(&metrics.requestsErrors)
	if after != before+1 {
		t.Errorf("expected errors counter to increment by 1, got %d -> %d", before, after)
	}
}
