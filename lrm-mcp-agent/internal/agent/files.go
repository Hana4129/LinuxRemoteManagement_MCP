package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func readFile(path string, maxFileSizeMB int) (string, error) {
	// policy層と同一の正規化を適用し、認可したパスと実際に読むパスを一致させる
	cleanPath := filepath.Clean(strings.ReplaceAll(path, "\\", "/"))
	info, err := os.Stat(cleanPath)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("path is a directory")
	}
	maxBytes := int64(maxFileSizeMB) * 1024 * 1024
	if info.Size() > maxBytes {
		return "", fmt.Errorf("file too large: %d bytes (max %d MB)", info.Size(), maxFileSizeMB)
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return string(data), nil
}
