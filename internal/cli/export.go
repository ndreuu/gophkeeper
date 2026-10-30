package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func exportPrivateFile(path string, source io.Reader) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create new export file: %w", err)
	}
	defer func() {
		_ = file.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err := io.Copy(file, source); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("flush export file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close export file: %w", err)
	}
	return nil
}
