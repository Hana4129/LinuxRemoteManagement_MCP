package agent

import (
	"os/exec"
	"strings"
	"time"
)

type execResult struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Duration string `json:"duration"`
}

func executeCommand(command string) execResult {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return execResult{Command: command, ExitCode: 1, Stderr: "empty command"}
	}
	start := time.Now()
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Dir = "/tmp"
	out, err := cmd.CombinedOutput()
	duration := time.Since(start)
	result := execResult{
		Command:  command,
		Stdout:   string(out),
		Duration: duration.String(),
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = 1
		}
		result.Stderr = err.Error()
	}
	return result
}
