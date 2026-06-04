package logging

import (
	"io"
	"strings"

	"github.com/charmbracelet/log"
)

func NewLogger(w io.Writer, level string, json bool) *log.Logger {
	if !enabledLevel(level) {
		return log.New(io.Discard)
	}

	formatter := log.TextFormatter
	if json {
		formatter = log.JSONFormatter
	}

	parsed, err := log.ParseLevel(strings.ToLower(strings.TrimSpace(level)))
	if err != nil {
		parsed = log.InfoLevel
	}

	return log.NewWithOptions(w, log.Options{
		Level:           parsed,
		Formatter:       formatter,
		ReportTimestamp: true,
	})
}

func enabledLevel(level string) bool {
	level = strings.ToUpper(strings.TrimSpace(level))
	return level != "" && level != "NONE"
}
