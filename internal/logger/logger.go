package logger

import (
	"log/slog"
	"os"

	"github.com/altafino/email-extractor/internal/types"
)

// parseLevel converts string level to slog.Level
func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Setup creates a new logger based on configuration
func Setup(cfg *types.Config) *slog.Logger {
	level := parseLevel(cfg.Logging.Level)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.Logging.IncludeCaller,
	}

	var handler slog.Handler
	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
