package logging

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"

	charmlog "github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/settings"
)

var (
	nopOnce   sync.Once
	nopLogger *charmlog.Logger
)

func New(cfg settings.LogSettings) *charmlog.Logger {
	output := io.Writer(os.Stderr)
	if !enabledLevel(cfg.Level) {
		output = io.Discard
	}

	formatter := charmlog.TextFormatter
	if cfg.JSON {
		formatter = charmlog.JSONFormatter
	}

	parsed, err := charmlog.ParseLevel(strings.ToLower(strings.TrimSpace(cfg.Level)))
	if err != nil {
		parsed = charmlog.InfoLevel
	}

	return charmlog.NewWithOptions(output, charmlog.Options{
		Level:           parsed,
		Formatter:       formatter,
		ReportTimestamp: true,
	})
}

func Nop() *charmlog.Logger {
	nopOnce.Do(func() {
		nopLogger = charmlog.NewWithOptions(io.Discard, charmlog.Options{
			Level:           charmlog.InfoLevel,
			ReportTimestamp: true,
		})
	})
	return nopLogger
}

func Resolve(logger *charmlog.Logger) *charmlog.Logger {
	if logger != nil {
		return logger
	}
	return Nop()
}

func IntoContext(ctx context.Context, logger *charmlog.Logger) context.Context {
	return context.WithValue(ctx, charmlog.ContextKey, Resolve(logger))
}

func enabledLevel(level string) bool {
	level = strings.ToUpper(strings.TrimSpace(level))
	return level != "" && level != "NONE"
}
