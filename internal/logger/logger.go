package logger

import (
	"log/slog"
	"os"

	"github.com/altafino/email-extractor/internal/types"
	"github.com/golang-cz/devslog"
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

	var handler slog.Handler
	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     level,
			AddSource: cfg.Logging.IncludeCaller,
		})
	} else {
		opts := &devslog.Options{
			MaxSlicePrintSize: 4,
			SortKeys:          true,
			TimeFormat:        "[04:05]",
			NewLineAfterLog:   true,
			DebugColor:        devslog.Magenta,
			StringerFormatter: true,
		}
		// Use devslog for text format - it provides better developer experience
		handler = devslog.NewHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}