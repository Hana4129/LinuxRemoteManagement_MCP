package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config は lrm-mcp-agent の設定全体を表す。
type Config struct {
	Agent AgentConfig `yaml:"agent"`
}

type AgentConfig struct {
	Name      string          `yaml:"name"`
	Listen    string          `yaml:"listen"`
	DataDir   string          `yaml:"data_dir"`
	Env       string          `yaml:"env"`
	TLS       TLSConfig       `yaml:"tls"`
	Tokens    []TokenEntry    `yaml:"tokens"`
	Allowlist Allowlist       `yaml:"allowlist"`
	RateLimit RateLimit       `yaml:"rate_limit"`
	Audit     AuditConfig     `yaml:"audit"`
	Execution ExecutionConfig `yaml:"execution"`
}

type TLSConfig struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	AutoCertFile string `yaml:"auto_cert_file"`
	AutoKeyFile  string `yaml:"auto_key_file"`
	// ClientCAFile は mTLS 用: クライアント証明書の検証に使う CA 証明書ファイル。
	// 設定すると、クライアント証明書の提示と検証が必須になる (RequireAndVerifyClientCert)。
	ClientCAFile string `yaml:"client_ca_file"`
}

type TokenEntry struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Hash     string   `yaml:"hash"`
	Scope    string   `yaml:"scope"`
	Commands []string `yaml:"commands"`
	Services []string `yaml:"services"`
	Files    []string `yaml:"files"`
	Disabled bool     `yaml:"disabled"`
}

type Allowlist struct {
	Commands      []string `yaml:"commands"`
	Services      []string `yaml:"services"`
	AllowedPaths  []string `yaml:"allowed_paths"`
	DeniedPaths   []string `yaml:"denied_paths"`
	WritePaths    []string `yaml:"write_paths"`
	MaxFileSizeMB int      `yaml:"max_file_size_mb"`
}

type RateLimit struct {
	Enabled   bool `yaml:"enabled"`
	PerMinute int  `yaml:"per_minute"`
	Burst     int  `yaml:"burst"`
}

type AuditConfig struct {
	Enabled     bool         `yaml:"enabled"`
	LogFile     string       `yaml:"log_file"`
	SIEM        SIEMConfig   `yaml:"siem"`
	AppendOnly  bool         `yaml:"append_only"`
}

type SIEMConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	APIKey     string `yaml:"api_key"`
	Format     string `yaml:"format"` // "json", "cef", "leef"
}

type ExecutionConfig struct {
	CommandTimeoutSeconds int `yaml:"command_timeout_seconds"`
}

// Load は指定パスのYAML設定を読み込み、デフォルト値を適用する。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Agent.Name == "" {
		cfg.Agent.Name = "lrm-mcp-agent"
	}
	if cfg.Agent.Listen == "" {
		cfg.Agent.Listen = ":8443"
	}
	if cfg.Agent.DataDir == "" {
		cfg.Agent.DataDir = "./data"
	}
	if cfg.Agent.Env == "" {
		cfg.Agent.Env = "production"
	}
	if cfg.Agent.TLS.AutoCertFile == "" {
		cfg.Agent.TLS.AutoCertFile = cfg.Agent.DataDir + "/server.crt"
	}
	if cfg.Agent.TLS.AutoKeyFile == "" {
		cfg.Agent.TLS.AutoKeyFile = cfg.Agent.DataDir + "/server.key"
	}
	if cfg.Agent.Allowlist.MaxFileSizeMB == 0 {
		cfg.Agent.Allowlist.MaxFileSizeMB = 10
	}
	if cfg.Agent.RateLimit.PerMinute == 0 {
		cfg.Agent.RateLimit.PerMinute = 60
	}
	if cfg.Agent.RateLimit.Burst == 0 {
		cfg.Agent.RateLimit.Burst = 10
	}
	if cfg.Agent.Audit.LogFile == "" {
		cfg.Agent.Audit.LogFile = cfg.Agent.DataDir + "/audit.log"
	}
	if cfg.Agent.Execution.CommandTimeoutSeconds == 0 {
		cfg.Agent.Execution.CommandTimeoutSeconds = 30
	}
	return &cfg, nil
}

// GenerateToken は CSPRNG で生トークンを生成する。
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "lra_" + hex.EncodeToString(b), nil
}
