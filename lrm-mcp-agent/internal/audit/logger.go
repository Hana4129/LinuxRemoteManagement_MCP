package audit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RotationConfig defines log rotation settings
type RotationConfig struct {
	MaxSizeMB  int  // Max size of each log file in MB
	MaxBackups int  // Max number of backup files to keep
	Compress   bool // Whether to compress backup files
}

// DefaultRotationConfig returns default rotation settings
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		MaxSizeMB:  10,
		MaxBackups: 5,
		Compress:   true,
	}
}

// SIEMConfig defines SIEM forwarding settings
type SIEMConfig struct {
	Enabled    bool   // Whether SIEM forwarding is enabled
	WebhookURL string // SIEM webhook URL
	APIKey     string // API key for authentication
	Format     string // Log format: "json", "cef", "leef"
}

// DefaultSIEMConfig returns default SIEM settings
func DefaultSIEMConfig() SIEMConfig {
	return SIEMConfig{
		Enabled: false,
		Format:  "json",
	}
}

type Logger struct {
	mu        sync.Mutex
	file      *os.File
	enabled   bool
	logFile   string
	config    RotationConfig
	lastHash  string // ハッシュチェーンの末尾 (Immutable Audit Log)
	siem      SIEMConfig
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
	PrevHash  string `json:"prev_hash,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

// New creates a new Logger with default rotation config
func New(logFile string, enabled bool) (*Logger, error) {
	return NewWithConfig(logFile, enabled, DefaultRotationConfig())
}

// NewWithConfig creates a new Logger with custom rotation config
func NewWithConfig(logFile string, enabled bool, config RotationConfig) (*Logger, error) {
	return NewWithFullConfig(logFile, enabled, config, DefaultSIEMConfig())
}

// NewWithFullConfig creates a new Logger with all configs
func NewWithFullConfig(logFile string, enabled bool, config RotationConfig, siemConfig SIEMConfig) (*Logger, error) {
	if !enabled {
		return &Logger{enabled: false}, nil
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	l := &Logger{
		file:     f,
		enabled:  true,
		logFile:  logFile,
		config:   config,
		siem:     siemConfig,
	}
	// 再起動後もチェーンを継続するため、既存ログの末尾ハッシュを復元する
	l.lastHash = readLastHash(logFile)
	return l, nil
}

// readLastHash はログファイル末尾のエントリのハッシュを読み取る (無ければ空文字)。
func readLastHash(logFile string) string {
	data, err := os.ReadFile(logFile)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[len(lines)-1]) == "" {
		return ""
	}
	var entry Entry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		return ""
	}
	return entry.Hash
}

// Verify はログファイル全体のハッシュチェーンを検証し、改ざんがあればエラーを返す。
// 先頭エントリの prev_hash が空でない場合は、前のログファイルへの参照とみなして許容する。
func Verify(logFile string) error {
	data, err := os.ReadFile(logFile)
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var prevHash string
	for i, rawLine := range lines {
		if strings.TrimSpace(rawLine) == "" {
			continue
		}
		var entry Entry
		if err := json.Unmarshal([]byte(rawLine), &entry); err != nil {
			return fmt.Errorf("invalid JSON at line %d: %w", i+1, err)
		}
		if entry.PrevHash != prevHash {
			return fmt.Errorf("hash chain broken at line %d: prev=%q want=%q", i+1, entry.PrevHash, prevHash)
		}
		computed := entry.computeHash()
		if computed != entry.Hash {
			return fmt.Errorf("tampering detected at line %d: stored=%q computed=%q", i+1, entry.Hash, computed)
		}
		prevHash = entry.Hash
	}
	return nil
}

// VerifyChain はロガーが持つログパスの完全性を検証する。
func (l *Logger) VerifyChain() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Verify(l.logFile)
}

// LastHash は現在のハッシュチェーン末尾を返す (監視・外部保管用)。
func (l *Logger) LastHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastHash
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
		PrevHash:  l.lastHash,
	}
	// Immutable Audit Log: ハッシュチェーンによる改ざん防止
	entry.Hash = entry.computeHash()
	l.lastHash = entry.Hash
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if rotation is needed before writing
	l.rotateIfNeeded()

	l.file.Write(data)
	l.file.Write([]byte("\n"))

	// SIEM転送 (非同期)
	if l.siem.Enabled && l.siem.WebhookURL != "" {
		go l.forwardToSIEM(data)
	}
}

// forwardToSIEM sends audit log entry to SIEM webhook
func (l *Logger) forwardToSIEM(data []byte) {
	if l.siem.WebhookURL == "" {
		return
	}

	// CEF/LEEF形式への変換
	payload := l.formatForSIEM(data)

	req, err := http.NewRequest("POST", l.siem.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("SIEM forward error: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if l.siem.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+l.siem.APIKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("SIEM forward failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("SIEM forward returned status %d", resp.StatusCode)
	}
}

// formatForSIEM converts audit entry to the configured format
func (l *Logger) formatForSIEM(data []byte) []byte {
	if l.siem.Format == "json" || l.siem.Format == "" {
		return data
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return data
	}

	switch l.siem.Format {
	case "cef":
		return []byte(l.toCEF(entry))
	case "leef":
		return []byte(l.toLEEF(entry))
	default:
		return data
	}
}

// toCEF converts entry to CEF (Common Event Format)
func (l *Logger) toCEF(e Entry) string {
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	return fmt.Sprintf(
		"CEF:0|LRM|MCP-Agent|1.0|%s|%s|%s|src=%s actor=%s resource=%s result=%s msg=%s",
		e.Action, e.Action, l.severity(e.Result), e.ClientIP, e.Actor, e.Resource, e.Result, e.Detail,
	)
}

// toLEEF converts entry to LEEF (Log Event Extended Format)
func (l *Logger) toLEEF(e Entry) string {
	return fmt.Sprintf(
		"LEEF:2.0|LRM|MCP-Agent|1.0|%s\tcat=%s\tdevTime=%s\tsrc=%s\tactor=%s\tresource=%s\tresult=%s\tmsg=%s",
		e.Action, e.Action, e.Timestamp, e.ClientIP, e.Actor, e.Resource, e.Result, e.Detail,
	)
}

func (l *Logger) severity(result string) string {
	switch result {
	case "denied", "error":
		return "7"
	case "timeout":
		return "5"
	default:
		return "3"
	}
}

// computeHash はエントリの全フィールド + 直前ハッシュから SHA-256 を計算する。
// JSON のフィールド追加・順序変更でハッシュが変わらないよう、明示的に連結する。
func (e Entry) computeHash() string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.Timestamp, e.Level, e.Actor, e.Action, e.Resource,
		e.Result, e.Detail, e.ClientIP, e.PrevHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// rotateIfNeeded checks if the log file exceeds max size and rotates if needed
func (l *Logger) rotateIfNeeded() {
	if l.config.MaxSizeMB <= 0 {
		return
	}

	info, err := l.file.Stat()
	if err != nil {
		log.Printf("Failed to stat log file: %v", err)
		return
	}

	maxBytes := int64(l.config.MaxSizeMB) * 1024 * 1024
	if info.Size() < maxBytes {
		return
	}

	// Perform rotation
	l.rotate()
}

// rotate closes the current log file and creates a new one
func (l *Logger) rotate() {
	// Close current file
	if l.file != nil {
		l.file.Close()
	}

	// Rotate existing backup files
	for i := l.config.MaxBackups - 1; i >= 0; i-- {
		var oldPath string
		if i == 0 {
			oldPath = l.logFile
		} else {
			oldPath = fmt.Sprintf("%s.%d", l.logFile, i)
			if l.config.Compress {
				oldPath += ".gz"
			}
		}

		newPath := fmt.Sprintf("%s.%d", l.logFile, i+1)
		if l.config.Compress {
			newPath += ".gz"
		}

		if _, err := os.Stat(oldPath); err == nil {
			if i == l.config.MaxBackups-1 {
				// Delete oldest backup
				os.Remove(oldPath)
			} else {
				// Rename to next index
				os.Rename(oldPath, newPath)
			}
		}
	}

	// Compress the rotated file if enabled
	if l.config.Compress {
		compressedPath := l.logFile + ".1.gz"
		if err := compressFile(l.logFile, compressedPath); err != nil {
			log.Printf("Failed to compress rotated log: %v", err)
		}
	}

	// Create new log file
	f, err := os.OpenFile(l.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("Failed to create new log file: %v", err)
		return
	}
	l.file = f
}

// compressFile compresses a file using gzip
func compressFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination file: %w", err)
	}
	defer destFile.Close()

	gzWriter := gzip.NewWriter(destFile)
	defer gzWriter.Close()

	buf := make([]byte, 4096)
	for {
		n, err := sourceFile.Read(buf)
		if n > 0 {
			gzWriter.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	// Remove original file after successful compression
	os.Remove(src)
	return nil
}

// Backup performs a manual log rotation
func (l *Logger) Backup() {
	if !l.enabled || l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rotate()
}

// GetLogFilePath returns the current log file path
func (l *Logger) GetLogFilePath() string {
	return l.logFile
}

// GetBackupFiles returns a list of backup file paths
func (l *Logger) GetBackupFiles() []string {
	var backups []string
	for i := 1; i <= l.config.MaxBackups; i++ {
		path := fmt.Sprintf("%s.%d", l.logFile, i)
		if l.config.Compress {
			path += ".gz"
		}
		if _, err := os.Stat(path); err == nil {
			backups = append(backups, path)
		}
	}
	return backups
}

// Dir returns the directory of the log file
func (l *Logger) Dir() string {
	return filepath.Dir(l.logFile)
}

func (l *Logger) Shutdown() {
	if l.file != nil {
		l.file.Close()
	}
}
