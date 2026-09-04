package agent

import (
	"strings"
	"testing"
	"time"
)

func TestExecuteCommand_Success(t *testing.T) {
	result := executeCommand("echo hello")
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "hello") {
		t.Errorf("expected stdout to contain 'hello', got %q", result.Stdout)
	}
	if result.Stderr != "" {
		t.Errorf("expected no stderr, got %q", result.Stderr)
	}
}

func TestExecuteCommand_EmptyCommand(t *testing.T) {
	result := executeCommand("")
	if result.ExitCode != 1 {
		t.Errorf("expected exit code 1 for empty command, got %d", result.ExitCode)
	}
	if result.Stderr != "empty command" {
		t.Errorf("expected 'empty command' stderr, got %q", result.Stderr)
	}
}

func TestExecuteCommand_InvalidCommand(t *testing.T) {
	result := executeCommand("nonexistent_command_xyz")
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code for invalid command")
	}
}

func TestExecuteCommand_WithArguments(t *testing.T) {
	result := executeCommand("echo hello world")
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "hello world") {
		t.Errorf("expected stdout to contain 'hello world', got %q", result.Stdout)
	}
}

func TestExecuteCommand_CommandField(t *testing.T) {
	result := executeCommand("echo test")
	if result.Command != "echo test" {
		t.Errorf("expected command field to be 'echo test', got %q", result.Command)
	}
}

func TestExecuteCommand_Duration(t *testing.T) {
	result := executeCommand("echo test")
	if result.Duration == "" {
		t.Error("expected duration to be set")
	}
}

func TestExecuteCommandWithTimeout_NotTimedOut(t *testing.T) {
	result := executeCommandWithTimeout("echo quick", 5*time.Second)
	if result.TimedOut {
		t.Error("expected quick command not to time out")
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "quick") {
		t.Errorf("expected stdout to contain 'quick', got %q", result.Stdout)
	}
}

func TestExecuteCommandWithTimeout_TimesOut(t *testing.T) {
	// sleep longer than the timeout
	result := executeCommandWithTimeout("sleep 5", 500*time.Millisecond)
	if !result.TimedOut {
		t.Error("expected command to time out")
	}
	if result.ExitCode != 124 {
		t.Errorf("expected exit code 124 for timeout, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stderr, "timed out") {
		t.Errorf("expected stderr to contain 'timed out', got %q", result.Stderr)
	}
}

func TestExecuteCommandWithTimeout_ZeroTimeout(t *testing.T) {
	// Zero timeout should fall back to default and not immediately fail
	result := executeCommandWithTimeout("echo test", 0)
	if result.TimedOut {
		t.Error("expected command not to time out with fallback default")
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestValidateCommand_CleanCommands(t *testing.T) {
	cleanCommands := []string{
		"echo hello",
		"systemctl restart nginx",
		"/usr/bin/systemctl restart docker",
		"df -B1",
		"ps -eo pid",
	}
	for _, cmd := range cleanCommands {
		if reason := validateCommand(cmd); reason != "" {
			t.Errorf("expected %q to be valid, got rejection: %s", cmd, reason)
		}
	}
}

func TestValidateCommand_ShellMetachars(t *testing.T) {
	unsafeCommands := map[string]string{
		"echo hello; rm -rf /":       ";",
		"echo hello & rm -rf /":      "&",
		"echo hello | cat":           "|",
		"echo `whoami`":              "`",
		"echo $(whoami)":             "$(",
		"echo ${HOME}":               "${",
		"echo hello > /etc/passwd":   ">",
		"echo hello < /etc/passwd":   "<",
		"echo hello\nrm -rf /":       "\n",
		"echo hello && rm -rf /":     "&",
		"echo hello || rm -rf /":     "|",
	}
	for cmd, expected := range unsafeCommands {
		reason := validateCommand(cmd)
		if reason == "" {
			t.Errorf("expected %q to be rejected", cmd)
		} else if expected == "$(" || expected == "${" {
			if !strings.Contains(reason, "subshell") {
				t.Errorf("expected subshell rejection for %q, got: %s", cmd, reason)
			}
		} else if !strings.Contains(reason, expected) {
			t.Errorf("expected rejection of %q to mention %q, got: %s", cmd, expected, reason)
		}
	}
}

func TestValidateCommand_Empty(t *testing.T) {
	if reason := validateCommand(""); reason == "" {
		t.Error("expected empty command to be rejected")
	}
	if reason := validateCommand("   "); reason == "" {
		t.Error("expected whitespace-only command to be rejected")
	}
}

func TestExecuteCommand_RejectsInjection(t *testing.T) {
	result := executeCommand("echo hello; rm -rf /")
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code for injection attempt")
	}
	if !strings.Contains(result.Stderr, "forbidden shell metacharacter") {
		t.Errorf("expected rejection message, got %q", result.Stderr)
	}
}

func TestSanitizeEnv(t *testing.T) {
	env := sanitizeEnv()
	if len(env) == 0 {
		t.Error("expected non-empty sanitized environment")
	}
	for _, e := range env {
		if !strings.Contains(e, "=") {
			t.Errorf("expected environment entry with '=', got %q", e)
		}
	}
}

