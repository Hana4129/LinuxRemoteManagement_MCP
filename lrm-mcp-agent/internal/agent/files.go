package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// readFile opens path for reading after strict traversal validation:
//   - the path must be absolute (relative paths are rejected)
//   - symlinks are resolved and the resolved path must equal the
//     authorized (cleaned) path, otherwise traversal is detected
//   - the file size must not exceed maxFileSizeMB
func readFile(path string, maxFileSizeMB int) (string, error) {
	// policy層と同一の正規化を適用し、認可したパスと実際に読むパスを一致させる
	cleanPath := filepath.Clean(strings.ReplaceAll(path, "\\", "/"))

	// 相対パスは完全に禁止 (認可判定との不一致を防ぐ)
	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("relative paths are not allowed: %s", cleanPath)
	}

	// シンボリックリンクを解決し、認可済みパスと一致することを検証する。
	// リンク先が許可パス外 (例: /etc/os-release -> /home/user/secret) の場合は拒否。
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	// OS差異 (セパレータ等) を吸収してから比較する
	resolvedClean := filepath.ToSlash(filepath.Clean(resolved))
	if resolvedClean != filepath.ToSlash(cleanPath) {
		return "", fmt.Errorf("symlink traversal detected: %s resolves to %s", cleanPath, resolved)
	}

	// 解決後のパスに対して最終確認 (TOCTOU緩和のため解決後パスを使用)
	info, err := os.Stat(resolved)
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
	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return string(data), nil
}

// writeFile replaces the content of path after strict traversal validation.
// The existing file (if any) is backed up to <path>.bak before overwriting.
// Writing is destructive, so the caller must have authorized the path via
// policy.CanWriteFile beforehand.
func writeFile(path, content string, maxFileSizeMB int) (backupPath string, err error) {
	cleanPath := filepath.Clean(strings.ReplaceAll(path, "\\", "/"))

	// 相対パスは完全に禁止
	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("relative paths are not allowed: %s", cleanPath)
	}

	// シンボリックリンクは追跡しない (既存ファイルがリンクなら拒否)
	info, err := os.Lstat(cleanPath)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("symlinks cannot be written through: %s", cleanPath)
	case err == nil && info.IsDir():
		return "", fmt.Errorf("path is a directory")
	}

	maxBytes := int64(maxFileSizeMB) * 1024 * 1024
	if int64(len(content)) > maxBytes {
		return "", fmt.Errorf("content too large: %d bytes (max %d MB)", len(content), maxFileSizeMB)
	}

	// 既存ファイルをバックアップしてから上書きする
	if err == nil {
		backupPath = cleanPath + ".bak"
		orig, readErr := os.ReadFile(cleanPath)
		if readErr != nil {
			return "", fmt.Errorf("backup read: %w", readErr)
		}
		if writeErr := os.WriteFile(backupPath, orig, 0o600); writeErr != nil {
			return "", fmt.Errorf("backup write: %w", writeErr)
		}
	}

	if err := os.WriteFile(cleanPath, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	return backupPath, nil
}
