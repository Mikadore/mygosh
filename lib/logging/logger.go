package logging

import (
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/settings"
)

func Configure(cfg settings.LogSettings) {
	output := io.Writer(os.Stderr)
	if !enabledLevel(cfg.Level) {
		output = io.Discard
	}

	formatter := log.TextFormatter
	if cfg.JSON {
		formatter = log.JSONFormatter
	}

	parsed, err := log.ParseLevel(strings.ToLower(strings.TrimSpace(cfg.Level)))
	if err != nil {
		parsed = log.InfoLevel
	}

	log.SetDefault(log.NewWithOptions(output, log.Options{
		Level:           parsed,
		Formatter:       formatter,
		ReportTimestamp: true,
	}))
}

func enabledLevel(level string) bool {
	level = strings.ToUpper(strings.TrimSpace(level))
	return level != "" && level != "NONE"
}
