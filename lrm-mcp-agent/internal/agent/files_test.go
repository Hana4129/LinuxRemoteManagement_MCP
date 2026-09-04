package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFile_Success(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-read-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	expectedContent := "hello world"
	if _, err := tmp.WriteString(expectedContent); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	content, err := readFile(tmp.Name(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != expectedContent {
		t.Errorf("expected %q, got %q", expectedContent, content)
	}
}

func TestReadFile_NonexistentFile(t *testing.T) {
	_, err := readFile("/nonexistent/path/file.txt", 10)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadFile_Directory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-dir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	_, err = readFile(tmpDir, 10)
	if err == nil {
		t.Error("expected error when reading directory")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected 'directory' in error message, got %v", err)
	}
}

func TestReadFile_TooLarge(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-large-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	// Write 2MB of data
	data := make([]byte, 2*1024*1024)
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	// Max file size is 1MB
	_, err = readFile(tmp.Name(), 1)
	if err == nil {
		t.Error("expected error for file too large")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' in error message, got %v", err)
	}
}

func TestReadFile_ExceedsMaxSize(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-size-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	// Write 5MB of data
	data := make([]byte, 5*1024*1024)
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	// Max file size is 1MB
	_, err = readFile(tmp.Name(), 1)
	if err == nil {
		t.Error("expected error for file exceeding max size")
	}
}

func TestReadFile_ValidSize(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-valid-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	// Write 500KB of data
	data := make([]byte, 500*1024)
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	// Max file size is 1MB
	content, err := readFile(tmp.Name(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(content) != 500*1024 {
		t.Errorf("expected content length %d, got %d", 500*1024, len(content))
	}
}

func TestReadFile_RejectsRelativePath(t *testing.T) {
	// 相対パスは完全に拒否される
	_, err := readFile("etc/os-release", 10)
	if err == nil {
		t.Error("expected error for relative path")
	}
	if !strings.Contains(err.Error(), "relative") {
		t.Errorf("expected 'relative' in error message, got %v", err)
	}
}

func TestReadFile_RejectsSymlinkTraversal(t *testing.T) {
	// シンボリックリンクはWindowsでは作成に権限が必要なためスキップ
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	// リンク経由の読み取りは拒否される（解決後パスが認可パスと一致しないため）
	_, err := readFile(link, 10)
	if err == nil {
		t.Error("expected error when reading through symlink")
	}
	if !strings.Contains(err.Error(), "symlink traversal") {
		t.Errorf("expected 'symlink traversal' in error message, got %v", err)
	}
}

func TestReadFile_RegularFileStillWorks(t *testing.T) {
	// 通常ファイルはシンボリックリンク検知に影響されず読める
	dir := t.TempDir()
	target := filepath.Join(dir, "normal.txt")
	if err := os.WriteFile(target, []byte("normal content"), 0o600); err != nil {
		t.Fatal(err)
	}

	content, err := readFile(target, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "normal content" {
		t.Errorf("expected 'normal content', got %q", content)
	}
}

func TestWriteFile_NewFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "new.txt")

	backup, err := writeFile(target, "hello", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if backup != "" {
		t.Errorf("expected no backup for new file, got %q", backup)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data))
	}
}

func TestWriteFile_OverwriteWithBackup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	backup, err := writeFile(target, "new content", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if backup != target+".bak" {
		t.Errorf("expected backup path %q, got %q", target+".bak", backup)
	}
	backupData, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(backupData) != "old" {
		t.Errorf("expected backup content 'old', got %q", string(backupData))
	}
	data, _ := os.ReadFile(target)
	if string(data) != "new content" {
		t.Errorf("expected 'new content', got %q", string(data))
	}
}

func TestWriteFile_RejectsRelativePath(t *testing.T) {
	_, err := writeFile("etc/test.txt", "x", 10)
	if err == nil {
		t.Error("expected error for relative path")
	}
	if !strings.Contains(err.Error(), "relative") {
		t.Errorf("expected 'relative' in error message, got %v", err)
	}
}

func TestWriteFile_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	_, err := writeFile(link, "evil", 10)
	if err == nil {
		t.Error("expected error when writing through symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected 'symlink' in error message, got %v", err)
	}
}

func TestWriteFile_TooLargeContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "large.txt")

	_, err := writeFile(target, strings.Repeat("x", 2*1024*1024), 1)
	if err == nil {
		t.Error("expected error for content too large")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' in error message, got %v", err)
	}
}

func TestReadFile_CleanPath(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-clean-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err = tmp.WriteString("test"); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	// Test with backslashes (Windows-style)
	backSlashPath := strings.ReplaceAll(tmp.Name(), string(filepath.Separator), "\\")
	content, err := readFile(backSlashPath, 10)
	if err != nil {
		t.Fatalf("unexpected error with backslash path: %v", err)
	}
	if content != "test" {
		t.Errorf("expected 'test', got %q", content)
	}
}
