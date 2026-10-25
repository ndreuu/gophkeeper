package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type config struct {
	ServerURL string `json:"server_url"`
	CAFile    string `json:"ca_file"`
	StateFile string `json:"state_file"`
}

func parseConfig(args []string, out io.Writer) (config, []string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return config{}, nil, fmt.Errorf("find user configuration directory: %w", err)
	}
	cfg := config{ServerURL: "https://localhost:8443", StateFile: filepath.Join(base, "gophkeeper", "state.json")}
	var overrides config
	configFile := os.Getenv("GOPHKEEPER_CONFIG")
	fs := flag.NewFlagSet("gophkeeper", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(out, usage) }
	fs.StringVar(&configFile, "config", configFile, "JSON configuration file")
	fs.StringVar(&overrides.ServerURL, "server-url", "", "HTTPS server address")
	fs.StringVar(&overrides.CAFile, "ca-file", "", "trusted PEM CA certificate")
	fs.StringVar(&overrides.StateFile, "state-file", "", "session and encrypted cache file")
	if err := fs.Parse(args); err != nil {
		return config{}, nil, err
	}
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return config{}, nil, fmt.Errorf("read client configuration: %w", err)
		}
		if err := decodeJSON(strings.NewReader(string(data)), &cfg); err != nil {
			return config{}, nil, fmt.Errorf("decode client configuration: %w", err)
		}
	}
	for _, item := range []struct {
		env string
		dst *string
	}{
		{"GOPHKEEPER_SERVER_URL", &cfg.ServerURL},
		{"GOPHKEEPER_CA_FILE", &cfg.CAFile},
		{"GOPHKEEPER_STATE_FILE", &cfg.StateFile},
	} {
		if value, ok := os.LookupEnv(item.env); ok {
			*item.dst = value
		}
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server-url":
			cfg.ServerURL = overrides.ServerURL
		case "ca-file":
			cfg.CAFile = overrides.CAFile
		case "state-file":
			cfg.StateFile = overrides.StateFile
		}
	})
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
	if cfg.StateFile == "" {
		return config{}, nil, errors.New("state-file must not be empty")
	}
	return cfg, fs.Args(), nil
}

func decodeJSON(in io.Reader, dst any) error {
	dec := json.NewDecoder(in)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("expected a single JSON value")
		}
		return err
	}
	return nil
}
