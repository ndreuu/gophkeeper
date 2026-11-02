package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type failedExportReader struct{}

func (failedExportReader) Read([]byte) (int, error) {
	return 0, errors.New("export source failed")
}

func TestExportCreatesPrivateFileAndRefusesExistingDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "export.bin")
	if err := exportPrivateFile(path, strings.NewReader("private bytes")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("export permissions %o", info.Mode().Perm())
	}
	if err := exportPrivateFile(path, strings.NewReader("replacement")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing export was not refused: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "private bytes" {
		t.Fatalf("existing export was modified: %q: %v", data, err)
	}
}

func TestExportRefusesSymlinksAndPreservesTheirTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("existing target"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dangling := range []bool{false, true} {
		link := filepath.Join(dir, "link.bin")
		destination := target
		if dangling {
			link = filepath.Join(dir, "dangling.bin")
			destination = filepath.Join(dir, "missing.bin")
		}
		if err := os.Symlink(destination, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := exportPrivateFile(link, strings.NewReader("replacement")); !errors.Is(err, os.ErrExist) {
			t.Fatalf("symlink destination was not refused: %v", err)
		}
		info, err := os.Lstat(link)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("export modified the existing symlink: %v", err)
		}
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "existing target" {
		t.Fatalf("symlink target was modified: %q: %v", data, err)
	}
}

func TestExportRemovesItsPartialFileOnSourceFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.bin")
	source := io.MultiReader(strings.NewReader("partial private data"), failedExportReader{})
	if err := exportPrivateFile(path, source); err == nil {
		t.Fatal("source failure was ignored")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial plaintext export remains: %v", err)
	}
	if err := exportPrivateFile(filepath.Join(path, "nested.bin"), strings.NewReader("value")); err != nil {
		t.Fatal(err)
	}
	if err := exportPrivateFile(filepath.Join(path, "nested.bin", "child"), strings.NewReader("value")); err == nil {
		t.Fatal("export created a directory below an existing file")
	}
}
