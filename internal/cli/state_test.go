package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validState() state {
	return state{Version: 1, ServerURL: "https://localhost:8443", Token: "token", VaultSalt: []byte("1234567890abcdef"), ExpiresAt: time.Now().Add(time.Hour)}
}

func TestPrivateStateRoundTripAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.json")
	cfg := config{ServerURL: "https://localhost:8443", StateFile: path}
	if _, err := loadState(cfg); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("missing session: %v", err)
	}
	s := validState()
	if err := saveState(path, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadState(cfg)
	if err != nil || loaded.Token != s.Token {
		t.Fatalf("loaded %+v: %v", loaded, err)
	}
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", info.Mode().Perm())
	}
	cfg.ServerURL = "https://another.example"
	if _, err := loadState(cfg); err == nil {
		t.Fatal("accepted session for another server")
	}
	cfg.ServerURL = s.ServerURL
	for _, change := range []func(*state){func(s *state) { s.Version = 2 }, func(s *state) { s.Token = "" }, func(s *state) { s.VaultSalt = nil }, func(s *state) { s.ExpiresAt = time.Time{} }} {
		bad := validState()
		change(&bad)
		if err := saveState(path, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := loadState(cfg); err == nil {
			t.Fatal("accepted invalid session")
		}
	}
	if err := os.WriteFile(path, []byte(`{broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(cfg); err == nil {
		t.Fatal("accepted corrupt session")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadState(cfg); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("broad permissions: %v", err)
		}
	}
}

func TestStateRejectsNonRegularAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := config{ServerURL: "https://localhost:8443", StateFile: dir}
	if _, err := loadState(cfg); err == nil {
		t.Fatal("directory accepted as state")
	}
	path := filepath.Join(dir, "state.json")
	if err := saveState(path, validState()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err == nil {
		cfg.StateFile = link
		if _, err := loadState(cfg); err == nil {
			t.Fatal("symlink accepted")
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(maxStateSize + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg.StateFile = path
	if _, err := loadState(cfg); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized session: %v", err)
	}
	if err := writePrivateFile(filepath.Join(path, "child"), []byte("data")); err == nil {
		t.Fatal("created directory under a file")
	}
	if err := writePrivateFile(dir, []byte("data")); err == nil {
		t.Fatal("replaced directory")
	}
}
