package config

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadPriority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"address":"json:9000","database_dsn":"json-dsn","tls_cert":"json.crt","tls_key":"json.key","session_ttl":"2h","log_level":"warn"}`), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"GOPHKEEPER_CONFIG": path, "GOPHKEEPER_ADDRESS": "env:9001", "GOPHKEEPER_DATABASE_DSN": "env-dsn", "GOPHKEEPER_TLS_CERT": "env.crt", "GOPHKEEPER_TLS_KEY": "env.key", "GOPHKEEPER_SESSION_TTL": "3h", "GOPHKEEPER_LOG_LEVEL": "error"}
	cfg, err := Load([]string{"-a", "flag:9002", "-d", "flag-dsn", "-tls-cert", "flag.crt", "-tls-key", "flag.key", "-session-ttl", "4h", "-log-level", "debug"}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "flag:9002" || cfg.DatabaseDSN != "flag-dsn" || cfg.TLSCert != "flag.crt" || cfg.TLSKey != "flag.key" || cfg.SessionTTL != 4*time.Hour || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected flags %+v", cfg)
	}
	cfg, err = Load(nil, func(k string) string { return env[k] })
	if err != nil || cfg.Address != "env:9001" || cfg.SessionTTL != 3*time.Hour {
		t.Fatalf("environment priority %+v %v", cfg, err)
	}
	cfg, err = Load([]string{"-config", path}, func(string) string { return "" })
	if err != nil || cfg.Address != "json:9000" || cfg.SessionTTL != 2*time.Hour {
		t.Fatalf("JSON %+v %v", cfg, err)
	}
	cfg, err = Load([]string{"-database-dsn", "test"}, func(string) string { return "" })
	if err != nil || cfg.Address != "localhost:8443" || cfg.SessionTTL != 24*time.Hour {
		t.Fatalf("defaults %+v %v", cfg, err)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := [][]string{{}, {"-unknown"}, {"-d", "x", "extra"}, {"-d", "x", "-a", "bad"}, {"-d", "x", "-session-ttl", "0s"}, {"-d", "x", "-session-ttl", "forever"}, {"-d", "x", "-session-ttl", "721h"}, {"-d", "x", "-tls-cert", ""}, {"-d", "x", "-tls-key", ""}, {"-d", "x", "-log-level", "verbose"}, {"-c", "/does/not/exist"}}
	for _, args := range cases {
		t.Run(stringArgs(args), func(t *testing.T) {
			if _, err := Load(args, func(string) string { return "" }); err == nil {
				t.Fatalf("expected error %v", args)
			}
		})
	}
	if _, err := Load([]string{"-h"}, func(string) string { return "" }); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
	for _, content := range []string{`{`, `{"unknown":1}`, `{} {}`, `{"session_ttl":0}`} {
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load([]string{"-c", path}, func(string) string { return "" }); err == nil {
			t.Fatalf("accepted %s", content)
		}
	}
}
func stringArgs(args []string) string {
	if len(args) == 0 {
		return "missing-dsn"
	}
	return args[len(args)-1]
}
