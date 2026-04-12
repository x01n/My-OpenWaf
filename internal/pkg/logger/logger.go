package logger

import (
	"log/slog"
	"os"
	"strings"
)

func parseLevel() slog.Level {
	switch strings.ToUpper(strings.TrimSpace(os.Getenv("MY_OPENWAF_LOG_LEVEL"))) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New creates a structured JSON logger tagged with the given section.
// Section examples: "admin", "dataplane", "waf", "security", "auth".
// Output format: {"time":"...","level":"INFO","section":"admin","msg":"..."}
func New(section string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel()})
	return slog.New(h).With(slog.String("section", section))
}
