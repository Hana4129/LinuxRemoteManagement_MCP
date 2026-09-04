package agent

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DefaultCommandTimeout is the default timeout for command execution
const DefaultCommandTimeout = 30 * time.Second

// shellMetachars are characters that enable shell injection when present.
// Since exec.Command does not use a shell, these are rejected defensively:
// if any appear, the allowlist matching may have been bypassed.
const shellMetachars = ";&|`$><\n\r"

// validateCommand checks the command for shell injection patterns.
// Returns an error message if the command is unsafe, "" otherwise.
func validateCommand(command string) string {
	if strings.TrimSpace(command) == "" {
		return "empty command"
	}
	// Block subshell substitution patterns first (more specific diagnosis
	// before the generic metacharacter scan hits '$').
	if strings.Contains(command, "$(") || strings.Contains(command, "${") {
		return "command contains subshell substitution"
	}
	for _, ch := range shellMetachars {
		if strings.ContainsRune(command, ch) {
			return "command contains forbidden shell metacharacter: " + string(ch)
		}
	}
	return ""
}

// sanitizeEnv returns a minimal environment for executed commands
func sanitizeEnv() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/tmp",
		"LANG=C.UTF-8",
	}
}

// workingDir returns the directory commands run in: /tmp when available
// (Linux production), otherwise the agent's working directory
// (e.g. Windows development environments without /tmp).
func workingDir() string {
	if info, err := os.Stat("/tmp"); err == nil && info.IsDir() {
		return "/tmp"
	}
	return ""
}

type execResult struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Duration string `json:"duration"`
	TimedOut bool   `json:"timed_out"`
}

// executeCommand runs a command with the default timeout
func executeCommand(command string) execResult {
	return executeCommandWithTimeout(command, DefaultCommandTimeout)
}

// executeCommandWithTimeout runs a command with a specified timeout
func executeCommandWithTimeout(command string, timeout time.Duration) execResult {
	if reason := validateCommand(command); reason != "" {
		log.Printf("Command rejected by injection validation: %s", reason)
		return execResult{Command: command, ExitCode: 1, Stderr: reason}
	}
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return execResult{Command: command, ExitCode: 1, Stderr: "empty command"}
	}
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Dir = workingDir()
	cmd.Env = sanitizeEnv()
	out, err := cmd.CombinedOutput()
	duration := time.Since(start)
	result := execResult{
		Command:  command,
		Stdout:   string(out),
		Duration: duration.String(),
	}
	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = 124 // conventional exit code for timeout (like GNU timeout)
		result.Stderr = "command timed out after " + timeout.String()
		log.Printf("Command timed out after %s: %s", timeout, command)
		return result
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = 1
			result.Stderr = err.Error()
		}
	}
	log.Printf("Command executed in %s (exit=%d): %s", duration, result.ExitCode, command)
	return result
}
