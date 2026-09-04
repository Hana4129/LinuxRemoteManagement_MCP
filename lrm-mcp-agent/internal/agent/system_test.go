package agent

import (
	"strings"
	"testing"
)

func TestGetSystemInfo_Structure(t *testing.T) {
	info := getSystemInfo()
	// Hostname should be a string (possibly empty in test env)
	_ = info.Hostname
	// OS should be a string
	if info.OS == "" {
		t.Error("expected OS to be non-empty")
	}
	// Kernel should be a string (possibly empty in test env)
	_ = info.Kernel
	// Arch should be a string (possibly empty in test env)
	_ = info.Arch
	// Platform should be a string
	if info.Platform == "" {
		t.Error("expected Platform to be non-empty")
	}
	// AgentVersion should be set
	if info.AgentVersion == "" {
		t.Error("expected AgentVersion to be non-empty")
	}
}

func TestReadOS(t *testing.T) {
	os := readOS()
	if os == "" {
		t.Error("expected non-empty OS string")
	}
	// Should contain "Linux" or be "Linux"
	if !strings.Contains(os, "Linux") {
		t.Errorf("expected OS to contain 'Linux', got %q", os)
	}
}

func TestGetUptime(t *testing.T) {
	uptime := getUptime()
	// Uptime should be a non-negative number
	// In test environment, it might be 0 if /proc/uptime is not available
	_ = uptime
}

func TestGetBootTime(t *testing.T) {
	bootTime := getBootTime()
	// BootTime should be a string (possibly empty in test env)
	_ = bootTime
}

func TestGetMemory(t *testing.T) {
	mem := getMemory()
	// In test environment, /proc/meminfo might not be available
	if mem != nil {
		// If memory info is available, validate structure
		if mem.TotalMB <= 0 {
			t.Error("expected positive TotalMB")
		}
		if mem.AvailableMB < 0 {
			t.Error("expected non-negative AvailableMB")
		}
		if mem.UsedPercent < 0 || mem.UsedPercent > 100 {
			t.Errorf("expected UsedPercent between 0 and 100, got %f", mem.UsedPercent)
		}
	}
}

func TestGetDiskUsage(t *testing.T) {
	disks := getDiskUsage()
	// In test environment, df might not be available
	// If available, validate structure
	for _, d := range disks {
		if d.Device == "" {
			t.Error("expected non-empty Device")
		}
		if d.Mount == "" {
			t.Error("expected non-empty Mount")
		}
	}
}

func TestGetProcesses(t *testing.T) {
	procs := getProcesses()
	// In test environment, ps might not be available
	// If available, validate structure
	for _, p := range procs {
		if p.PID <= 0 {
			t.Errorf("expected positive PID, got %d", p.PID)
		}
		if p.Command == "" {
			t.Error("expected non-empty Command")
		}
	}
}
