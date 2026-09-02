package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu      sync.Mutex
	file    *os.File
	enabled bool
}

type Entry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Result    string `json:"result"`
	Detail    string `json:"detail,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
}

func New(logFile string, enabled bool) (*Logger, error) {
	if !enabled {
		return &Logger{enabled: false}, nil
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{file: f, enabled: true}, nil
}

func (l *Logger) Log(actor, action, resource, result, detail, clientIP string) {
	if !l.enabled || l.file == nil {
		return
	}
	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     "info",
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Result:    result,
		Detail:    detail,
		ClientIP:  clientIP,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.file.Write(data)
	l.file.Write([]byte("\n"))
}

func (l *Logger) Shutdown() {
	if l.file != nil {
		l.file.Close()
	}
}
