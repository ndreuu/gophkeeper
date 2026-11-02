package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const Usage = `Usage: server [flags]
  -c, -config FILE         JSON configuration (GOPHKEEPER_CONFIG)
  -a, -address HOST:PORT   HTTPS listen address (GOPHKEEPER_ADDRESS; localhost:8443)
  -d, -database-dsn DSN    PostgreSQL connection string (GOPHKEEPER_DATABASE_DSN)
  -tls-cert FILE          PEM server certificate (GOPHKEEPER_TLS_CERT; certs/server.crt)
  -tls-key FILE           PEM private key (GOPHKEEPER_TLS_KEY; certs/server.key)
  -session-ttl DURATION   Session lifetime (GOPHKEEPER_SESSION_TTL; 24h)
  -log-level LEVEL        Zap log level (GOPHKEEPER_LOG_LEVEL; info)
  -h                     Show this help
Priority: defaults < JSON < environment < explicit flags.
`

type Config struct {
	Address     string
	DatabaseDSN string
	TLSCert     string
	TLSKey      string
	SessionTTL  time.Duration
	LogLevel    string
}

type rawConfig struct {
	Address     string `json:"address"`
	DatabaseDSN string `json:"database_dsn"`
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`
	SessionTTL  string `json:"session_ttl"`
	LogLevel    string `json:"log_level"`
}

// Load parses args without the program name using getenv as its environment source.
// It returns flag.ErrHelp for -h; callers can print Usage without opening the database.
func Load(args []string, getenv func(string) string) (Config, error) {
	defaults := rawConfig{Address: "localhost:8443", TLSCert: "certs/server.crt", TLSKey: "certs/server.key", SessionTTL: "24h", LogLevel: "info"}
	flags := defaults
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var configFile string
	fs.StringVar(&configFile, "c", getenv("GOPHKEEPER_CONFIG"), "")
	fs.StringVar(&configFile, "config", getenv("GOPHKEEPER_CONFIG"), "")
	fs.StringVar(&flags.Address, "a", defaults.Address, "")
	fs.StringVar(&flags.Address, "address", defaults.Address, "")
	fs.StringVar(&flags.DatabaseDSN, "d", "", "")
	fs.StringVar(&flags.DatabaseDSN, "database-dsn", "", "")
	fs.StringVar(&flags.TLSCert, "tls-cert", defaults.TLSCert, "")
	fs.StringVar(&flags.TLSKey, "tls-key", defaults.TLSKey, "")
	fs.StringVar(&flags.SessionTTL, "session-ttl", defaults.SessionTTL, "")
	fs.StringVar(&flags.LogLevel, "log-level", defaults.LogLevel, "")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected server arguments")
	}
	raw := defaults
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return Config{}, fmt.Errorf("read configuration: %w", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&raw); err != nil {
			return Config{}, fmt.Errorf("decode configuration: %w", err)
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return Config{}, fmt.Errorf("configuration must contain one JSON object")
		}
	}
	bindings := map[string]*string{"GOPHKEEPER_ADDRESS": &raw.Address, "GOPHKEEPER_DATABASE_DSN": &raw.DatabaseDSN, "GOPHKEEPER_TLS_CERT": &raw.TLSCert, "GOPHKEEPER_TLS_KEY": &raw.TLSKey, "GOPHKEEPER_SESSION_TTL": &raw.SessionTTL, "GOPHKEEPER_LOG_LEVEL": &raw.LogLevel}
	for name, dest := range bindings {
		if value := getenv(name); value != "" {
			*dest = value
		}
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "a", "address":
			raw.Address = flags.Address
		case "d", "database-dsn":
			raw.DatabaseDSN = flags.DatabaseDSN
		case "tls-cert":
			raw.TLSCert = flags.TLSCert
		case "tls-key":
			raw.TLSKey = flags.TLSKey
		case "session-ttl":
			raw.SessionTTL = flags.SessionTTL
		case "log-level":
			raw.LogLevel = flags.LogLevel
		}
	})
	if _, _, err := net.SplitHostPort(raw.Address); err != nil {
		return Config{}, fmt.Errorf("address must be HOST:PORT")
	}
	if raw.DatabaseDSN == "" {
		return Config{}, fmt.Errorf("database-dsn is required")
	}
	if raw.TLSCert == "" || raw.TLSKey == "" {
		return Config{}, fmt.Errorf("TLS certificate and key are required")
	}
	ttl, err := time.ParseDuration(raw.SessionTTL)
	if err != nil || ttl <= 0 || ttl > 30*24*time.Hour {
		return Config{}, fmt.Errorf("session-ttl must be positive and at most 720h")
	}
	switch raw.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return Config{}, fmt.Errorf("log-level must be debug, info, warn or error")
	}
	return Config{Address: raw.Address, DatabaseDSN: raw.DatabaseDSN, TLSCert: raw.TLSCert, TLSKey: raw.TLSKey, SessionTTL: ttl, LogLevel: raw.LogLevel}, nil
}
