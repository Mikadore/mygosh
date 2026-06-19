package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	charmlog "github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/settings"
)

var (
	nopOnce   sync.Once
	nopLogger *slog.Logger
)

func New(cfg settings.LogSettings) *slog.Logger {
	return newWithOutput(cfg, os.Stderr)
}

func newWithOutput(cfg settings.LogSettings, output io.Writer) *slog.Logger {
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

	handler := charmlog.NewWithOptions(output, charmlog.Options{
		Level:           parsed,
		Formatter:       formatter,
		ReportTimestamp: true,
	})
	return slog.New(handler)
}

func Nop() *slog.Logger {
	nopOnce.Do(func() {
		handler := charmlog.NewWithOptions(io.Discard, charmlog.Options{
			Level:           charmlog.InfoLevel,
			ReportTimestamp: true,
		})
		nopLogger = slog.New(handler)
	})
	return nopLogger
}

func Resolve(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return Nop()
}

func enabledLevel(level string) bool {
	level = strings.ToUpper(strings.TrimSpace(level))
	return level != "" && level != "NONE"
}
