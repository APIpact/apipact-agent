// Package obs provides structured logging with secret redaction. The agent
// handles auth headers and response bodies that may contain credentials, so
// logs are deliberately conservative: they never print header values or bodies.
package obs

import (
	"log/slog"
	"os"
	"strings"
)

// New builds a JSON slog.Logger writing to stderr at the given level.
func New(level slog.Level, component string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("component", component)
}

// LevelFromEnv reads APIPACT_LOG_LEVEL (debug|info|warn|error), defaulting to info.
func LevelFromEnv() slog.Level {
	switch strings.ToLower(os.Getenv("APIPACT_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// RedactURL strips the query string and userinfo from a URL for safe logging;
// query strings frequently carry tokens.
func RedactURL(raw string) string {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i] + "?<redacted>"
	}
	if at := strings.LastIndex(raw, "@"); at >= 0 {
		if scheme := strings.Index(raw, "://"); scheme >= 0 && scheme+3 < at {
			raw = raw[:scheme+3] + "<redacted>@" + raw[at+1:]
		}
	}
	return raw
}
