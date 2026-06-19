package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"

	"github.com/Mikadore/mygosh/lib/settings"
)

var (
	nopOnce   sync.Once
	nopLogger *slog.Logger
)

type Service struct {
	logger         *slog.Logger
	consoleEnabled *atomic.Bool
	file           io.Closer
	closeOnce      sync.Once
	closeErr       error
}

func NewService(cfg settings.LogSettings) (*Service, error) {
	if enabledLevel(cfg.Level) && cfg.File != "" {
		logFile, err := openLogFile(cfg.File)
		if err != nil {
			return nil, err
		}
		return newService(cfg, os.Stderr, logFile, logFile), nil
	}

	return newService(cfg, os.Stderr, nil, nil), nil
}

func openLogFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, eris.Wrapf(err, "open log file %s", path)
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, errors.Join(
			eris.Wrapf(err, "set log file permissions %s", path),
			file.Close(),
		)
	}
	return file, nil
}

func newService(cfg settings.LogSettings, consoleOutput io.Writer, fileOutput io.Writer, file io.Closer) *Service {
	consoleEnabled := &atomic.Bool{}
	consoleEnabled.Store(true)

	var handlers []slog.Handler
	if enabledLevel(cfg.Level) {
		level := parseLevel(cfg.Level)
		handlers = append(handlers, switchHandler{
			enabled: consoleEnabled,
			next:    newConsoleHandler(consoleOutput, level, cfg.JSON),
		})
		if fileOutput != nil {
			handlers = append(handlers, slog.NewJSONHandler(fileOutput, &slog.HandlerOptions{
				Level: level,
			}))
		}
	}

	return &Service{
		logger:         slog.New(multiHandler(handlers)),
		consoleEnabled: consoleEnabled,
		file:           file,
	}
}

func (s *Service) Logger() *slog.Logger {
	if s == nil {
		return Nop()
	}
	return s.logger
}

func (s *Service) SetConsoleEnabled(enabled bool) {
	if s == nil {
		return
	}
	s.consoleEnabled.Store(enabled)
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.file != nil {
			s.closeErr = s.file.Close()
		}
	})
	return s.closeErr
}

func Nop() *slog.Logger {
	nopOnce.Do(func() {
		nopLogger = slog.New(multiHandler(nil))
	})
	return nopLogger
}

func Resolve(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return Nop()
}

func newConsoleHandler(output io.Writer, level slog.Level, jsonOutput bool) slog.Handler {
	formatter := charmlog.TextFormatter
	if jsonOutput {
		formatter = charmlog.JSONFormatter
	}

	return charmlog.NewWithOptions(output, charmlog.Options{
		Level:           charmlog.Level(level),
		Formatter:       formatter,
		ReportTimestamp: true,
	})
}

func parseLevel(level string) slog.Level {
	parsed, err := charmlog.ParseLevel(strings.ToLower(strings.TrimSpace(level)))
	if err != nil {
		return slog.LevelInfo
	}
	return slog.Level(parsed)
}

func enabledLevel(level string) bool {
	level = strings.ToUpper(strings.TrimSpace(level))
	return level != "" && level != "NONE"
}

type switchHandler struct {
	enabled *atomic.Bool
	next    slog.Handler
}

func (h switchHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.enabled.Load() && h.next.Enabled(ctx, level)
}

func (h switchHandler) Handle(ctx context.Context, record slog.Record) error {
	if !h.enabled.Load() {
		return nil
	}
	return h.next.Handle(ctx, record)
}

func (h switchHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return switchHandler{
		enabled: h.enabled,
		next:    h.next.WithAttrs(attrs),
	}
}

func (h switchHandler) WithGroup(name string) slog.Handler {
	return switchHandler{
		enabled: h.enabled,
		next:    h.next.WithGroup(name),
	}
}

type multiHandler []slog.Handler

func (h multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var err error
	for _, handler := range h {
		if handler.Enabled(ctx, record.Level) {
			err = errors.Join(err, handler.Handle(ctx, record.Clone()))
		}
	}
	return err
}

func (h multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make(multiHandler, 0, len(h))
	for _, handler := range h {
		handlers = append(handlers, handler.WithAttrs(attrs))
	}
	return handlers
}

func (h multiHandler) WithGroup(name string) slog.Handler {
	handlers := make(multiHandler, 0, len(h))
	for _, handler := range h {
		handlers = append(handlers, handler.WithGroup(name))
	}
	return handlers
}
