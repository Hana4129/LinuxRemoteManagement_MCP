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
	"github.com/internal/lrm-mcp-agent/internal/config"
)

var version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yml", "path to config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		log.Printf("lrm-mcp-agent %s", version)
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
	tlsCfg, err := agent.LoadOrGenerate(certFile, keyFile)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	a.Shutdown()
	log.Println("bye")
}
