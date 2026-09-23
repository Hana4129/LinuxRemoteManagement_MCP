package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/internal/lrm-mcp-agent/internal/config"
)

const usage = `credential-issue - Agent側でMCP Server用credentialを発行する

使い方:
  credential-issue -name <name> [-id <token-id>] [-scope readonly|operator] [-config config.yml] [-apply]

説明:
  CSPRNGで生トークンを生成し、SHA-256 hashをAgentのconfig.ymlへ登録する。
  生トークンは標準出力に一度だけ表示される。この生値をMCP Server (Console) の
  credential登録APIへ一度だけ提出すること。(-nameはConsole側credential nameと
  一致させること。省略時はConsoleがname一致でagent_token_idを自動解決する)

  -apply : config.ymlへtokenエントリを追記する (既存ファイルは .bak に退避)。
           未指定時はconfigスニペットの表示のみ行う。
`

func main() {
	configPath := flag.String("config", "config.yml", "path to agent config.yml")
	name := flag.String("name", "", "credential name (must match the Console-side credential name)")
	id := flag.String("id", "", "token id in config.yml (default: credential-<name>)")
	scope := flag.String("scope", "readonly", "token scope: readonly or operator")
	apply := flag.Bool("apply", false, "append the token entry to config.yml (creates .bak backup)")
	showUsage := flag.Bool("help", false, "show usage")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *showUsage {
		fmt.Print(usage)
		return
	}
	*name = strings.TrimSpace(*name)
	if *name == "" {
		fmt.Fprint(os.Stderr, usage)
		fmt.Fprintln(os.Stderr, "\nerror: -name is required")
		os.Exit(2)
	}
	if *scope != "readonly" && *scope != "operator" {
		fmt.Fprintf(os.Stderr, "error: -scope must be readonly or operator (got: %s)\n", *scope)
		os.Exit(2)
	}

	raw, err := config.GenerateToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: token generation failed: %v\n", err)
		os.Exit(1)
	}
	h := sha256.Sum256([]byte(raw))
	tokenHash := hex.EncodeToString(h[:])

	tokenID := strings.TrimSpace(*id)
	if tokenID == "" {
		tokenID = "credential-" + *name
	}

	if *apply {
		if err := appendToConfig(*configPath, tokenID, *name, tokenHash, *scope); err != nil {
			fmt.Fprintf(os.Stderr, "error: config.yml update failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "config.yml updated: token id=%s (backup: %s.bak)\n", tokenID, *configPath)
		fmt.Fprintf(os.Stderr, "config watcher が有効なら自動でreloadされます (無い場合はagentをreloadしてください)\n\n")
	} else {
		fmt.Fprintln(os.Stderr, "(-apply not specified: config.yml not updated. Append this snippet under tokens:)")
		fmt.Println()
	}

	fmt.Printf("# 提出用 (Consoleのcredential登録へ一度だけ提出 / 再表示されません)\n")
	fmt.Printf("curl -X POST https://<mcp-server>/api/agent-credentials \\\n")
	fmt.Printf("  -H \"Content-Type: application/json\" \\\n")
	fmt.Printf("  -d '{\"server_id\": \"<server-id>\", \"name\": %q, \"token\": %q}'\n", *name, raw)
	fmt.Println()
	fmt.Printf("raw_token: %s\n", raw)
}

func appendToConfig(path, tokenID, name, tokenHash, scope string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config read: %w", err)
	}
	if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
		return fmt.Errorf("backup write: %w", err)
	}
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("config parse: %w", err)
	}
	for _, t := range cfg.Agent.Tokens {
		if t.ID == tokenID {
			return fmt.Errorf("token id %q already exists in %s", tokenID, path)
		}
	}
	cfg.Agent.Tokens = append(cfg.Agent.Tokens, config.TokenEntry{
		ID:    tokenID,
		Name:  name,
		Hash:  tokenHash,
		Scope: scope,
	})
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("config marshal: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("config write: %w", err)
	}
	return nil
}
