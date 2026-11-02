package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte(`{"server_url":"https://json.example","ca_file":"json.pem","state_file":"json-state"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPHKEEPER_CONFIG", path)
	t.Setenv("GOPHKEEPER_SERVER_URL", "https://env.example/")
	t.Setenv("GOPHKEEPER_CA_FILE", "env.pem")
	t.Setenv("GOPHKEEPER_STATE_FILE", "env-state")
	cfg, args, err := parseConfig([]string{"-server-url", "https://flag.example/", "-ca-file", "flag.pem", "-state-file", "flag-state", "sync"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL != "https://flag.example" || cfg.CAFile != "flag.pem" || cfg.StateFile != "flag-state" || len(args) != 1 || args[0] != "sync" {
		t.Fatalf("flag precedence: %+v, %v", cfg, args)
	}
	cfg, _, err = parseConfig([]string{"sync"}, io.Discard)
	if err != nil || cfg.ServerURL != "https://env.example" || cfg.CAFile != "env.pem" || cfg.StateFile != "env-state" {
		t.Fatalf("env precedence: %+v: %v", cfg, err)
	}
}

func TestConfigValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	for _, data := range []string{`{"unknown":true}`, `{} {}`, `{broken`, `{"state_file":""}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := parseConfig([]string{"-config", path, "sync"}, io.Discard); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	if _, _, err := parseConfig([]string{"-config", filepath.Join(dir, "missing"), "sync"}, io.Discard); err == nil {
		t.Fatal("missing config accepted")
	}
	for _, data := range []string{`{} {}`, `{} broken`, `{"unknown":1}`} {
		var dst config
		if err := decodeJSON(strings.NewReader(data), &dst); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
