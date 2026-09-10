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
	result := getServiceLogs("nginx", 100)
	if result.Service != "nginx" {
		t.Errorf("expected service name 'nginx', got %q", result.Service)
	}
	// Lines should be a slice (possibly empty)
	_ = result.Lines
	_ = result.Total
	_ = result.Truncated
}

func TestGetServiceLogs_EmptyResult(t *testing.T) {
	result := getServiceLogs("nonexistent-service-xyz", 100)
	if result.Service != "nonexistent-service-xyz" {
		t.Errorf("expected service name 'nonexistent-service-xyz', got %q", result.Service)
	}
	// For nonexistent service, lines should be empty
	if len(result.Lines) != 0 {
		t.Errorf("expected empty lines for nonexistent service, got %d lines", len(result.Lines))
	}
}

// --- セキュリティ強化: バリデーションテスト ---

func TestValidateService_ValidNames(t *testing.T) {
	validNames := []string{
		"nginx.service",
		"docker.service",
		"postgresql@14-main.service",
		"sshd.service",
		"network.target",
		"cron.timer",
		"var.mount",
		"system.slice",
	}
	for _, name := range validNames {
		if err := validateService(name); err != nil {
			t.Errorf("expected %q to be valid, got error: %v", name, err)
		}
	}
}

func TestValidateService_InvalidNames(t *testing.T) {
	invalidNames := []string{
		"",                      // empty
		"nginx;rm -rf /",        // command injection
		"../../../etc/passwd",   // path traversal
		"nginx && cat /etc/shadow", // chaining
		"service with spaces",   // spaces
		"nginx\nmalicious",      // newline
		"a",                     // too short (no extension)
	}
	for _, name := range invalidNames {
		if err := validateService(name); err == nil {
			t.Errorf("expected %q to be rejected", name)
		}
	}
}

func TestValidateService_TooLong(t *testing.T) {
	longName := ""
	for i := 0; i < 300; i++ {
		longName += "a"
	}
	longName += ".service"
	if err := validateService(longName); err == nil {
		t.Error("expected long service name to be rejected")
	}
}

func TestValidateArguments_CleanArgs(t *testing.T) {
	cleanArgs := [][]string{
		{"nginx"},
		{"docker"},
		{"100"},
		{"is-active"},
		{"restart"},
		{"--no-pager"},
		{"-o", "cat"},
	}
	for _, args := range cleanArgs {
		if err := validateArguments(args); err != nil {
			t.Errorf("expected args %v to be valid, got error: %v", args, err)
		}
	}
}

func TestValidateArguments_DangerousArgs(t *testing.T) {
	dangerousArgs := [][]string{
		{"nginx;rm -rf /"},
		{"test|cat /etc/passwd"},
		{"hello`whoami`"},
		{"test$(id)"},
		{"${HOME}"},
		{"../etc/passwd"},
		{"..\\windows\\system32"},
		{"hello\nworld"},
	}
	for _, args := range dangerousArgs {
		if err := validateArguments(args); err == nil {
			t.Errorf("expected args %v to be rejected", args)
		}
	}
}

func TestRestrictSubcommand_Allowed(t *testing.T) {
	// systemctl is-active nginx
	if err := restrictSubcommand("systemctl", []string{"is-active", "nginx"}); err != nil {
		t.Errorf("expected systemctl is-active to be allowed, got: %v", err)
	}
	// systemctl restart nginx
	if err := restrictSubcommand("systemctl", []string{"restart", "nginx"}); err != nil {
		t.Errorf("expected systemctl restart to be allowed, got: %v", err)
	}
}

func TestRestrictSubcommand_Disallowed(t *testing.T) {
	// systemctl stop is not in allowed list
	if err := restrictSubcommand("systemctl", []string{"stop", "nginx"}); err == nil {
		t.Error("expected systemctl stop to be rejected")
	}
	// systemctl disable is not in allowed list
	if err := restrictSubcommand("systemctl", []string{"disable", "nginx"}); err == nil {
		t.Error("expected systemctl disable to be rejected")
	}
}

func TestGetServiceStatus_RejectsInvalid(t *testing.T) {
	// Invalid service name should return "invalid" status
	result := getServiceStatus("nginx;rm -rf /")
	if result.Status != "invalid" {
		t.Errorf("expected status 'invalid' for dangerous service name, got %q", result.Status)
	}
	if result.Active {
		t.Error("expected dangerous service name to be inactive")
	}
}

func TestRestartService_RejectsInvalid(t *testing.T) {
	result := restartService("../../etc/passwd")
	if result.Status != "invalid" {
		t.Errorf("expected status 'invalid' for path traversal, got %q", result.Status)
	}
	if result.Success {
		t.Error("expected path traversal to fail")
	}
}

func TestGetServiceLogs_RejectsInvalid(t *testing.T) {
	result := getServiceLogs("service;injection", 100)
	if len(result.Lines) != 0 {
		t.Errorf("expected empty lines for invalid service, got %d", len(result.Lines))
	}
}
