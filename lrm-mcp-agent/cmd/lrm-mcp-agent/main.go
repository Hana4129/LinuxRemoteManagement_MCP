package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/internal/lrm-mcp-agent/internal/agent"
	"github.com/internal/lrm-mcp-agent/internal/audit"
	"github.com/internal/lrm-mcp-agent/internal/config"
)

var version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yml", "path to config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	verifyFlag := flag.String("verify-audit", "", "verify audit log integrity (specify log file path)")
	flag.Parse()

	if *versionFlag {
		log.Printf("lrm-mcp-agent %s", version)
		return
	}

	// 監査ログ検証モード
	if *verifyFlag != "" {
		log.Printf("Verifying audit log: %s", *verifyFlag)
		if err := audit.Verify(*verifyFlag); err != nil {
			log.Fatalf("Audit log verification FAILED: %v", err)
		}
		log.Println("Audit log verification PASSED: integrity confirmed")
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}
	if err := os.MkdirAll(cfg.Agent.DataDir, 0o700); err != nil {
		log.Fatalf("data dir create failed: %v", err)
	}

	a, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("agent init failed: %v", err)
	}

	// 証明書が無ければ自己署名証明書を自動生成する
	certFile, keyFile := cfg.Agent.TLS.CertFile, cfg.Agent.TLS.KeyFile
	if certFile == "" || keyFile == "" {
		certFile, keyFile = cfg.Agent.TLS.AutoCertFile, cfg.Agent.TLS.AutoKeyFile
	}
	tlsCfg, err := agent.LoadOrGenerateWithClientCA(certFile, keyFile, cfg.Agent.TLS.ClientCAFile)
	if err != nil {
		log.Fatalf("tls setup failed: %v", err)
	}

	srv := &http.Server{
		Addr:         cfg.Agent.Listen,
		Handler:      a.Handler(),
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 設定ホットリロード (config.yml 変更を検知してトークン/ポリシーを更新)
	watcher, err := config.NewWatcher(*configPath, 5*time.Second, a.Reload)
	if err != nil {
		log.Printf("config watcher disabled: %v", err)
	} else {
		watcher.Start()
		log.Printf("config watcher started (interval=5s, path=%s)", *configPath)
	}

	go func() {
		log.Printf("lrm-mcp-agent %s listening on https://%s (env=%s)", version, cfg.Agent.Listen, cfg.Agent.Env)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	if watcher != nil {
		watcher.Stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	a.Shutdown()
	log.Println("bye")
}
