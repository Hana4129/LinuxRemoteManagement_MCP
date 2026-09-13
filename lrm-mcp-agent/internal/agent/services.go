package agent

import (
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// serviceNamePattern は許可されるsystemdサービス名のパターン。
// 英数字・ハイフン・アンダースコア・ドット・@記号のみ許可し、
// パストラバーサルやシェルメタ文字を排除する。
// 有効な拡張子: service, socket, target, timer, mount, automont,
//
//	swap, device, path, slice, scope
var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.\-]+(@[a-zA-Z0-9_.\-]*)?\.(service|socket|target|timer|mount|automount|swap|device|path|slice|scope)$`)

// dangerousArgPatterns は実行を拒否する引数パターン。
// シェルメタ文字、パストラバーサル、コマンドインジェクション試行を検出する。
var dangerousArgPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;|&` + "`" + `$><\n\r]`),
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`\$\(`),
	regexp.MustCompile(`\$\{`),
}

// allowedSubcommands は各コマンドで許可されるサブコマンドのマップ。
// キー: コマンド名, 値: 許可されるサブコマンドのセット。
var allowedSubcommands = map[string]map[string]bool{
	"systemctl": {
		"is-active": true,
		"restart":   true,
	},
	"journalctl": {
		"-u":         true,
		"-n":         true,
		"--no-pager": true,
		"-o":         true,
	},
}

// validateService はサービス名を厳密に検証する。
// systemdサービス名として有効な形式かどうかを判定する。
func validateService(service string) error {
	if service == "" {
		return &validationError{reason: "service name is empty"}
	}
	if len(service) > 256 {
		return &validationError{reason: "service name too long (max 256)"}
	}
	if !serviceNamePattern.MatchString(service) {
		return &validationError{reason: "invalid service name format: " + service}
	}
	return nil
}

// validateArguments コマンド引数の安全性を検証する。
// 危険なパターンが含まれている場合はエラーを返す。
func validateArguments(args []string) error {
	for _, arg := range args {
		for _, pattern := range dangerousArgPatterns {
			if pattern.MatchString(arg) {
				return &validationError{reason: "dangerous argument detected: " + arg}
			}
		}
	}
	return nil
}

// restrictSubcommand は許可されたサブコマンドのみを実行する。
// 定義されていないコマンドの場合は全引数を検証する。
func restrictSubcommand(command string, args []string) error {
	allowed, exists := allowedSubcommands[command]
	if !exists {
		// 未定義コマンドの場合は一般的な引数検証のみ実施
		return validateArguments(args)
	}
	subcommandSeen := false
	for _, arg := range args {
		// フラグ形式 (--xxx) は許可リスト対象外なので一般検証のみ
		if strings.HasPrefix(arg, "--") {
			if err := validateArguments([]string{arg}); err != nil {
				return err
			}
			continue
		}
		// オプション値 (-n 100 の 100 など) はスキップ
		if strings.HasPrefix(arg, "-") && len(arg) == 2 {
			continue
		}
		// 先頭の非オプション引数をサブコマンドとして許可リストで検証する。
		// 2番目以降 (サービス名等の引数) はサブコマンドではなく一般検証のみ行う。
		if !subcommandSeen {
			if !allowed[arg] {
				return &validationError{reason: "subcommand not allowed: " + arg + " (allowed: " + joinKeys(allowed) + ")"}
			}
			subcommandSeen = true
			continue
		}
		if err := validateArguments([]string{arg}); err != nil {
			return err
		}
	}
	return nil
}

// validationError はバリデーション失敗の理由を保持する。
type validationError struct {
	reason string
}

func (e *validationError) Error() string {
	return e.reason
}

// joinKeys はマップのキーをカンマ区切りで結合する。
func joinKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

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
	if err := validateService(service); err != nil {
		log.Printf("Service validation failed: %s", err)
		return serviceStatus{Service: service, Active: false, Status: "invalid"}
	}
	if err := restrictSubcommand("systemctl", []string{"is-active", service}); err != nil {
		log.Printf("Subcommand restriction failed: %s", err)
		return serviceStatus{Service: service, Active: false, Status: "rejected"}
	}
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
	if err := validateService(service); err != nil {
		log.Printf("Service validation failed: %s", err)
		return restartResult{Success: false, Service: service, Status: "invalid"}
	}
	if err := restrictSubcommand("systemctl", []string{"restart", service}); err != nil {
		log.Printf("Subcommand restriction failed: %s", err)
		return restartResult{Success: false, Service: service, Status: "rejected"}
	}
	cmd := exec.Command("systemctl", "restart", service)
	err := cmd.Run()
	if err != nil {
		return restartResult{Success: false, Service: service, Status: "failed"}
	}
	return restartResult{Success: true, Service: service, Status: "running"}
}

func getServiceLogs(service string, lines int) serviceLogs {
	if err := validateService(service); err != nil {
		log.Printf("Service validation failed: %s", err)
		return serviceLogs{Service: service, Lines: []string{}, Total: 0, Truncated: false}
	}
	// OpenAPI 契約: lines は 1〜1000 (既定 100)
	if lines <= 0 {
		lines = 100
	}
	if lines > 1000 {
		lines = 1000
	}
	if err := restrictSubcommand("journalctl", []string{"-u", service, "-n", strconv.Itoa(lines), "--no-pager", "-o", "cat"}); err != nil {
		log.Printf("Subcommand restriction failed: %s", err)
		return serviceLogs{Service: service, Lines: []string{}, Total: 0, Truncated: false}
	}
	out, err := exec.Command("journalctl", "-u", service, "-n", strconv.Itoa(lines), "--no-pager", "-o", "cat").Output()
	if err != nil {
		return serviceLogs{Service: service, Lines: []string{}, Total: 0, Truncated: false}
	}
	logLines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(logLines) == 1 && logLines[0] == "" {
		logLines = []string{}
	}
	return serviceLogs{
		Service:   service,
		Lines:     logLines,
		Total:     len(logLines),
		Truncated: len(logLines) >= lines,
	}
}
