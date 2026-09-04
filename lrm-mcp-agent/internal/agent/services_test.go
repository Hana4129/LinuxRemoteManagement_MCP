package agent

import (
	"testing"
)

func TestGetServiceStatus_Active(t *testing.T) {
	// systemd is not available in test environment, so we test the structure
	result := getServiceStatus("nginx")
	if result.Service != "nginx" {
		t.Errorf("expected service name 'nginx', got %q", result.Service)
	}
	// Status should be a string (empty or actual status)
	_ = result.Status
}

func TestGetServiceStatus_Nonexistent(t *testing.T) {
	result := getServiceStatus("nonexistent-service-xyz")
	if result.Service != "nonexistent-service-xyz" {
		t.Errorf("expected service name 'nonexistent-service-xyz', got %q", result.Service)
	}
	// For nonexistent service, active should be false
	if result.Active {
		t.Error("expected nonexistent service to be inactive")
	}
}

func TestRestartService_Structure(t *testing.T) {
	// systemd is not available in test environment
	result := restartService("nginx")
	if result.Service != "nginx" {
		t.Errorf("expected service name 'nginx', got %q", result.Service)
	}
	// Result should have success and status fields
	_ = result.Success
	_ = result.Status
}

func TestGetServiceLogs_Structure(t *testing.T) {
	// systemd is not available in test environment
	result := getServiceLogs("nginx")
	if result.Service != "nginx" {
		t.Errorf("expected service name 'nginx', got %q", result.Service)
	}
	// Lines should be a slice (possibly empty)
	_ = result.Lines
	_ = result.Total
	_ = result.Truncated
}

func TestGetServiceLogs_EmptyResult(t *testing.T) {
	result := getServiceLogs("nonexistent-service-xyz")
	if result.Service != "nonexistent-service-xyz" {
		t.Errorf("expected service name 'nonexistent-service-xyz', got %q", result.Service)
	}
	// For nonexistent service, lines should be empty
	if len(result.Lines) != 0 {
		t.Errorf("expected empty lines for nonexistent service, got %d lines", len(result.Lines))
	}
}
