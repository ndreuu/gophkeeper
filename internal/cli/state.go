package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

const maxStateSize = 128 << 20

type state struct {
	Version   int            `json:"version"`
	ServerURL string         `json:"server_url"`
	Token     string         `json:"token"`
	VaultSalt []byte         `json:"vault_salt"`
	ExpiresAt time.Time      `json:"expires_at"`
	Records   []model.Record `json:"records"`
}

func loadState(cfg config) (state, error) {
	info, err := os.Lstat(cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, errors.New("not logged in; run register or login")
	}
	if err != nil {
		return state{}, fmt.Errorf("inspect session file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return state{}, errors.New("session file must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return state{}, errors.New("session file permissions are too broad; set them to 0600")
	}
	if info.Size() > maxStateSize {
		return state{}, errors.New("session cache exceeds size limit")
	}
	file, err := os.Open(cfg.StateFile)
	if err != nil {
		return state{}, fmt.Errorf("open session file: %w", err)
	}
	defer file.Close()
	var s state
	if err := decodeJSON(io.LimitReader(file, maxStateSize+1), &s); err != nil {
		return state{}, fmt.Errorf("decode session file: %w", err)
	}
	if s.Version != 1 || s.Token == "" || len(s.VaultSalt) != 16 || s.ExpiresAt.IsZero() {
		return state{}, errors.New("invalid session file; log in again")
	}
	if s.ServerURL != cfg.ServerURL {
		return state{}, errors.New("session belongs to another server; choose a separate state-file or log in again")
	}
	return s, nil
}

func saveState(path string, s state) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode encrypted session cache: %w", err)
	}
	if len(data) > maxStateSize {
		return errors.New("session cache exceeds size limit")
	}
	return writePrivateFile(path, data)
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create private file directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".gophkeeper-*")
	if err != nil {
		return fmt.Errorf("create private temporary file: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("secure private file: %w", err)
	}
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write private file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush private file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close private file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace private file: %w", err)
	}
	return nil
}
