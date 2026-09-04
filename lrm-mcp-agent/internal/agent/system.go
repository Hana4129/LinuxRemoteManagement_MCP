package agent

import (
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type systemInfo struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Kernel       string   `json:"kernel"`
	Arch         string   `json:"arch"`
	Platform     string   `json:"platform"`
	Uptime       uint64   `json:"uptime_seconds"`
	BootTime     string   `json:"boot_time"`
	AgentVersion string   `json:"agent_version"`
	Memory       *memInfo `json:"memory,omitempty"`
}

type memInfo struct {
	TotalMB     int64   `json:"total_mb"`
	AvailableMB int64   `json:"available_mb"`
	UsedPercent float64 `json:"used_percent"`
}

func getSystemInfo() systemInfo {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Failed to get hostname: %v", err)
		hostname = "unknown"
	}

	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		log.Printf("Failed to get kernel version: %v", err)
	}
	kernel := strings.TrimSpace(string(out))

	out, err = exec.Command("uname", "-m").Output()
	if err != nil {
		log.Printf("Failed to get architecture: %v", err)
	}
	arch := strings.TrimSpace(string(out))

	info := systemInfo{
		Hostname:     hostname,
		OS:           readOS(),
		Kernel:       kernel,
		Arch:         arch,
		Platform:     "Linux " + arch,
		Uptime:       getUptime(),
		BootTime:     getBootTime(),
		AgentVersion: "0.1.0",
	}
	if m := getMemory(); m != nil {
		info.Memory = m
	}
	return info
}

func readOS() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		log.Printf("Failed to read /etc/os-release: %v", err)
		return "Linux"
	}
	lines := strings.Split(string(data), "\n")
	name := ""
	version := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	if name != "" {
		if version != "" {
			return name + " " + version
		}
		return name
	}
	return "Linux"
}

func getUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		log.Printf("Failed to read /proc/uptime: %v", err)
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		log.Printf("Empty /proc/uptime")
		return 0
	}
	sec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		log.Printf("Failed to parse uptime: %v", err)
		return 0
	}
	return uint64(sec)
}

func getBootTime() string {
	upt := getUptime()
	if upt == 0 {
		return "unknown"
	}
	boot := time.Now().Add(-time.Duration(upt) * time.Second)
	return boot.Format("2006-01-02 15:04:05")
}

func getMemory() *memInfo {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		log.Printf("Failed to read /proc/meminfo: %v", err)
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var total, available int64
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				total, err = strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					log.Printf("Failed to parse MemTotal: %v", err)
				}
			}
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				available, err = strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					log.Printf("Failed to parse MemAvailable: %v", err)
				}
			}
		}
	}
	if total == 0 {
		log.Printf("Memory total is 0, cannot calculate memory info")
		return nil
	}
	return &memInfo{
		TotalMB:     total / 1024,
		AvailableMB: available / 1024,
		UsedPercent: float64(total-available) / float64(total) * 100,
	}
}

type diskEntry struct {
	Device     string  `json:"device"`
	Mount      string  `json:"mount"`
	FSType     string  `json:"fstype"`
	TotalGB    float64 `json:"total_gb"`
	UsedGB     float64 `json:"used_gb"`
	AvailGB    float64 `json:"available_gb"`
	UsePercent float64 `json:"use_percent"`
}

func getDiskUsage() []diskEntry {
	out, err := exec.Command("df", "-B1", "--output=source,target,fstype,size,used,avail,pcent").Output()
	if err != nil {
		log.Printf("Failed to execute df command: %v", err)
		return nil
	}
	var entries []diskEntry
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			log.Printf("Unexpected df output format: %s", line)
			continue
		}
		total, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			log.Printf("Failed to parse disk total: %v", err)
			continue
		}
		used, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			log.Printf("Failed to parse disk used: %v", err)
			continue
		}
		avail, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			log.Printf("Failed to parse disk avail: %v", err)
			continue
		}
		pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[6], "%"), 64)
		if err != nil {
			log.Printf("Failed to parse disk percent: %v", err)
			continue
		}
		entries = append(entries, diskEntry{
			Device:     fields[0],
			Mount:      fields[1],
			FSType:     fields[2],
			TotalGB:    float64(total) / (1024 * 1024 * 1024),
			UsedGB:     float64(used) / (1024 * 1024 * 1024),
			AvailGB:    float64(avail) / (1024 * 1024 * 1024),
			UsePercent: pct,
		})
	}
	return entries
}

type procEntry struct {
	PID        int     `json:"pid"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	Command    string  `json:"command"`
}

func getProcesses() []procEntry {
	out, err := exec.Command("ps", "-eo", "pid,user:12,pcpu,pmem,comm", "--no-headers").Output()
	if err != nil {
		log.Printf("Failed to execute ps command: %v", err)
		return nil
	}
	var entries []procEntry
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			log.Printf("Unexpected ps output format: %s", line)
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			log.Printf("Failed to parse PID: %v", err)
			continue
		}
		cpu, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			log.Printf("Failed to parse CPU percent: %v", err)
			continue
		}
		mem, err := strconv.ParseFloat(fields[3], 64)
		if err != nil {
			log.Printf("Failed to parse memory percent: %v", err)
			continue
		}
		entries = append(entries, procEntry{
			PID:        pid,
			User:       fields[1],
			CPUPercent: cpu,
			MemPercent: mem,
			Command:    strings.Join(fields[4:], " "),
		})
		if i >= 100 {
			break
		}
	}
	return entries
}
