package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/internal/lrm-mcp-agent/internal/config"
)

const usage = `credential-issue - Agent側でMCP Server用credentialを発行し、Agent設定を安全に更新する

使い方 (credential発行):
  credential-issue -name <name> [-id <token-id>] [-scope readonly|operator] [-config config.yml] [-apply]
                   [-registration-file <path> -server-id <server-id>] [-raw-token-file <path>]

使い方 (Agent管理トークンのhash設定):
  credential-issue -set-admin-token -admin-token-file <path|-> [-config config.yml] [-replace-admin-token]

説明:
  (発行モード) CSPRNGで生トークンを生成し、SHA-256 hashをAgentのconfig.ymlへ登録する。
  生トークンの受け渡し方法は次の2通り:
    - 既定: 標準出力に一度だけ表示する (Console登録用のcurl例つき)
    - -registration-file / -raw-token-file: 端末・履歴・ログに出さず0600のファイルへ出力する
      -registration-file はConsole登録APIへそのままPOSTできるJSONを出力する
      (agent_token_id を埋め込むためConsole側のAgent照会は不要。-server-id が必須)

  (管理トークン設定モード) -admin-token-file から管理secretを読み、SHA-256だけを
  config.yml の agent.admin_token_hash へ反映する。secret自体は保存も表示もしない。
  既存hashが異なる場合は上書きせずエラーになる (-replace-admin-token で明示的に置換)。
  admin_token_hash はConsoleからの失効同期 (private admin API) の認証に使う。

  -apply : config.ymlへtokenエントリを追記する (既存ファイルは .bak に退避 / 0600)。
           未指定時はtoken追記を行わない。token id の重複はエラーになる。
           既存のコメント・未知のキーは保持される。

終了コード: 0=成功 / 1=実行エラー / 2=引数エラー
`

func main() {
	configPath := flag.String("config", "config.yml", "path to agent config.yml")
	name := flag.String("name", "", "credential name (must match the Console-side credential name)")
	id := flag.String("id", "", "token id in config.yml (default: credential-<name>)")
	scope := flag.String("scope", "readonly", "token scope: readonly or operator")
	apply := flag.Bool("apply", false, "append the token entry to config.yml (creates .bak backup)")
	rawTokenFile := flag.String("raw-token-file", "", "write the raw token to this file (0600) instead of printing it")
	registrationFile := flag.String("registration-file", "", "write the Console registration JSON to this file (0600)")
	serverID := flag.String("server-id", "", "Console-side server id (required with -registration-file)")
	setAdminToken := flag.Bool("set-admin-token", false, "set agent.admin_token_hash from -admin-token-file")
	adminTokenFile := flag.String("admin-token-file", "-", "file holding the admin secret ('-' = stdin)")
	replaceAdminToken := flag.Bool("replace-admin-token", false, "allow overwriting an existing different admin_token_hash")
	showUsage := flag.Bool("help", false, "show usage")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *showUsage {
		fmt.Print(usage)
		return
	}

	if *setAdminToken {
		if err := runSetAdminToken(*configPath, *adminTokenFile, *replaceAdminToken); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	nameValue := strings.TrimSpace(*name)
	if nameValue == "" {
		fmt.Fprint(os.Stderr, usage)
		fmt.Fprintln(os.Stderr, "\nerror: -name is required (or use -set-admin-token)")
		os.Exit(2)
	}
	if *scope != "readonly" && *scope != "operator" {
		fmt.Fprintf(os.Stderr, "error: -scope must be readonly or operator (got: %s)\n", *scope)
		os.Exit(2)
	}
	serverIDValue := strings.TrimSpace(*serverID)
	if *registrationFile != "" && serverIDValue == "" {
		fmt.Fprintln(os.Stderr, "error: -server-id is required with -registration-file")
		os.Exit(2)
	}

	if err := runIssue(issueOptions{
		configPath:       *configPath,
		name:             nameValue,
		id:               strings.TrimSpace(*id),
		scope:            *scope,
		apply:            *apply,
		rawTokenFile:     *rawTokenFile,
		registrationFile: *registrationFile,
		serverID:         serverIDValue,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type issueOptions struct {
	configPath       string
	name             string
	id               string
	scope            string
	apply            bool
	rawTokenFile     string
	registrationFile string
	serverID         string
}

// runSetAdminToken は管理secretの SHA-256 だけを config.yml へ反映する。
//
// 既存hashが同一なら冪等 (何も書かない)。異なる場合は replace が true のときだけ置換する。
func runSetAdminToken(configPath, adminTokenFile string, replace bool) error {
	secret, err := config.ReadSecret(adminTokenFile)
	if err != nil {
		return err
	}
	hash := config.HashSecret(secret)
	changed, err := config.SetAdminTokenHash(configPath, hash, replace)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintf(os.Stderr, "config.yml updated: agent.admin_token_hash (backup: %s.bak)\n", configPath)
	} else {
		fmt.Fprintf(os.Stderr, "agent.admin_token_hash already up to date in %s (no change)\n", configPath)
	}
	// hash は秘密値そのものではないため、Console側設定との突き合わせ用に表示してよい。
	fmt.Printf("admin_token_hash=%s\n", hash)
	return nil
}

// runIssue は credential を発行し、config.yml への反映と提出用ペイロードの出力を行う。
func runIssue(opts issueOptions) error {
	raw, err := config.GenerateToken()
	if err != nil {
		return fmt.Errorf("token generation failed: %w", err)
	}
	tokenHash := config.HashSecret(raw)

	tokenID := opts.id
	if tokenID == "" {
		tokenID = "credential-" + opts.name
	}

	if opts.apply {
		entry := config.TokenEntry{ID: tokenID, Name: opts.name, Hash: tokenHash, Scope: opts.scope}
		if err := config.AppendTokenEntry(opts.configPath, entry); err != nil {
			return fmt.Errorf("config.yml update failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "config.yml updated: token id=%s (backup: %s.bak)\n", tokenID, opts.configPath)
		fmt.Fprintln(os.Stderr, "config watcher が有効なら自動でreloadされます (無効な場合はagentを再起動してください)")
	} else {
		fmt.Fprintln(os.Stderr, "-apply 未指定のため config.yml へは追記していません")
		fmt.Println()
		fmt.Println("# config.yml の agent.tokens へ追記するスニペット (hashのみ / 生値は含まれない)")
		fmt.Printf("- id: %s\n  name: %s\n  hash: %s\n  scope: %s\n",
			tokenID, opts.name, tokenHash, opts.scope)
	}

	if opts.registrationFile != "" {
		payload := map[string]string{
			"server_id":      opts.serverID,
			"name":           opts.name,
			"token":          raw,
			"agent_token_id": tokenID,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("registration payload marshal failed: %w", err)
		}
		if err := writeSecretFile(opts.registrationFile, append(body, '\n')); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "registration payload written: %s (0600)\n", opts.registrationFile)
	}

	if opts.rawTokenFile != "" {
		if err := writeSecretFile(opts.rawTokenFile, []byte(raw+"\n")); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "raw token written: %s (0600)\n", opts.rawTokenFile)
	}

	fmt.Fprintf(os.Stderr, "token id=%s name=%s scope=%s\n", tokenID, opts.name, opts.scope)
	if opts.rawTokenFile != "" || opts.registrationFile != "" {
		// 生値はファイル経由で受け渡すモードでは端末へ表示しない。
		return nil
	}

	// 後方互換: 生値とConsole登録用のcurl例を一度だけ表示する。
	fmt.Println()
	fmt.Println("# 提出用 (Consoleのcredential登録へ一度だけ提出 / 再表示されません)")
	fmt.Println("curl -X POST https://<mcp-server>/api/agent-credentials \\")
	fmt.Println("  -H \"Content-Type: application/json\" \\")
	fmt.Printf("  -d '{\"server_id\": \"<server-id>\", \"name\": %q, \"token\": %q, \"agent_token_id\": %q}'\n",
		opts.name, raw, tokenID)
	fmt.Println()
	fmt.Printf("raw_token: %s\n", raw)
	return nil
}

// writeSecretFile は secret を 0600 のファイルへ書き出す (既存ファイルの権限も矯正する)。
func writeSecretFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
