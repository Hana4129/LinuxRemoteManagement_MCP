package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/internal/lrm-mcp-agent/internal/config"
)

func main() {
	tok, err := config.GenerateToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	hash := sha256.Sum256([]byte(tok))
	fmt.Printf("token: %s\n", tok)
	fmt.Printf("hash:  %s\n", hex.EncodeToString(hash[:]))
}
