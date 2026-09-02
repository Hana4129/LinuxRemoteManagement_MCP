package agent

import (
	"os/exec"
	"strings"
)

type serviceStatus struct {
	Service string `json:"service"`
	Active  bool   `json:"active"`
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
}

type serviceLogs struct {
	Service   string   `json:"service"`
	Lines     []string `json:"lines"`
	Total     int      `json:"total"`
	Truncated bool     `json:"truncated"`
}

type restartResult struct {
	Success bool   `json:"success"`
	Service string `json:"service"`
	Status  string `json:"status"`
}

func getServiceStatus(service string) serviceStatus {
	out, err := exec.Command("systemctl", "is-active", service).Output()
	status := strings.TrimSpace(string(out))
	active := err == nil && status == "active"
	return serviceStatus{
		Service: service,
		Active:  active,
		Status:  status,
		Enabled: false,
	}
}

func restartService(service string) restartResult {
	cmd := exec.Command("systemctl", "restart", service)
	err := cmd.Run()
	if err != nil {
		return restartResult{Success: false, Service: service, Status: "failed"}
	}
	return restartResult{Success: true, Service: service, Status: "running"}
}

func getServiceLogs(service string) serviceLogs {
	out, err := exec.Command("journalctl", "-u", service, "-n", "100", "--no-pager", "-o", "cat").Output()
	if err != nil {
		return serviceLogs{Service: service, Lines: []string{}, Total: 0, Truncated: false}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = []string{}
	}
	return serviceLogs{
		Service:   service,
		Lines:     lines,
		Total:     len(lines),
		Truncated: len(lines) >= 100,
	}
}
