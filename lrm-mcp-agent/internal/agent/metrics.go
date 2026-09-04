package agent

import (
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// Metrics holds various metrics for the agent
type Metrics struct {
	requestsTotal   int64
	requestsErrors  int64
	authSuccess     int64
	authFailures    int64
	rateLimitHits   int64
	startTime       time.Time
}

var metrics = &Metrics{
	startTime: time.Now(),
}

// IncrementRequests increments the total request counter
func IncrementRequests() {
	atomic.AddInt64(&metrics.requestsTotal, 1)
}

// IncrementErrors increments the error counter
func IncrementErrors() {
	atomic.AddInt64(&metrics.requestsErrors, 1)
}

// IncrementAuthSuccess increments the authentication success counter
func IncrementAuthSuccess() {
	atomic.AddInt64(&metrics.authSuccess, 1)
}

// IncrementAuthFailures increments the authentication failure counter
func IncrementAuthFailures() {
	atomic.AddInt64(&metrics.authFailures, 1)
}

// IncrementRateLimitHits increments the rate limit hit counter
func IncrementRateLimitHits() {
	atomic.AddInt64(&metrics.rateLimitHits, 1)
}

// handleMetrics returns Prometheus-format metrics
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	uptime := time.Since(metrics.startTime).Seconds()
	requestsTotal := atomic.LoadInt64(&metrics.requestsTotal)
	requestsErrors := atomic.LoadInt64(&metrics.requestsErrors)
	authSuccess := atomic.LoadInt64(&metrics.authSuccess)
	authFailures := atomic.LoadInt64(&metrics.authFailures)
	rateLimitHits := atomic.LoadInt64(&metrics.rateLimitHits)

	// System metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Prometheus format output
	fmt.Fprintf(w, "# HELP lrm_agent_requests_total Total number of requests\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_requests_total counter\n")
	fmt.Fprintf(w, "lrm_agent_requests_total %d\n", requestsTotal)

	fmt.Fprintf(w, "# HELP lrm_agent_requests_errors_total Total number of error responses\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_requests_errors_total counter\n")
	fmt.Fprintf(w, "lrm_agent_requests_errors_total %d\n", requestsErrors)

	fmt.Fprintf(w, "# HELP lrm_agent_auth_success_total Total number of successful authentications\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_auth_success_total counter\n")
	fmt.Fprintf(w, "lrm_agent_auth_success_total %d\n", authSuccess)

	fmt.Fprintf(w, "# HELP lrm_agent_auth_failures_total Total number of authentication failures\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_auth_failures_total counter\n")
	fmt.Fprintf(w, "lrm_agent_auth_failures_total %d\n", authFailures)

	fmt.Fprintf(w, "# HELP lrm_agent_rate_limit_hits_total Total number of rate limit hits\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_rate_limit_hits_total counter\n")
	fmt.Fprintf(w, "lrm_agent_rate_limit_hits_total %d\n", rateLimitHits)

	fmt.Fprintf(w, "# HELP lrm_agent_uptime_seconds Agent uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_uptime_seconds gauge\n")
	fmt.Fprintf(w, "lrm_agent_uptime_seconds %.2f\n", uptime)

	fmt.Fprintf(w, "# HELP lrm_agent_memory_bytes Current memory usage in bytes\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_memory_bytes gauge\n")
	fmt.Fprintf(w, "lrm_agent_memory_bytes %d\n", memStats.Alloc)

	fmt.Fprintf(w, "# HELP lrm_agent_cpu_goroutines Number of goroutines\n")
	fmt.Fprintf(w, "# TYPE lrm_agent_cpu_goroutines gauge\n")
	fmt.Fprintf(w, "lrm_agent_cpu_goroutines %d\n", runtime.NumGoroutine())
}
