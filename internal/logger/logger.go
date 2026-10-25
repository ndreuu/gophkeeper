package logger

import "go.uber.org/zap"

// New creates a production JSON logger at level; unsupported levels return an error.
func New(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	if err := cfg.Level.UnmarshalText([]byte(level)); err != nil {
		return nil, err
	}
	return cfg.Build()
}
