package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
)

type PrettyHandler struct {
	w      io.Writer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
	mu     *sync.Mutex
}

func NewLogger(w io.Writer, level string, json bool) *slog.Logger {
	if !enabledLevel(level) {
		return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	}

	parsed := parseLevel(level)
	opts := &slog.HandlerOptions{Level: parsed}
	if json {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(NewPrettyHandler(w, opts))
}

func NewPrettyHandler(w io.Writer, opts *slog.HandlerOptions) *PrettyHandler {
	var level slog.Leveler
	if opts != nil {
		level = opts.Level
	}
	return &PrettyHandler{
		w:     w,
		level: level,
		mu:    &sync.Mutex{},
	}
}

func enabledLevel(level string) bool {
	level = strings.ToUpper(strings.TrimSpace(level))
	return level != "" && level != "NONE"
}

func parseLevel(level string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	case "FATAL":
		return slog.LevelError + 4
	default:
		return slog.LevelInfo
	}
}

func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	min := slog.LevelInfo
	if h.level != nil {
		min = h.level.Level()
	}
	return level >= min
}

func (h *PrettyHandler) Handle(_ context.Context, record slog.Record) error {
	var line strings.Builder

	line.WriteString(dim)
	line.WriteString(record.Time.Format("15:04:05.000"))
	line.WriteString(reset)
	line.WriteByte(' ')
	line.WriteString(levelLabel(record.Level))
	line.WriteByte(' ')
	line.WriteString(bold)
	line.WriteString(record.Message)
	line.WriteString(reset)

	attrs := make([]slog.Attr, 0, len(h.attrs)+record.NumAttrs())
	attrs = append(attrs, h.attrs...)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})
	for _, attr := range attrs {
		h.appendAttr(&line, h.groups, attr)
	}

	line.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line.String())
	return err
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := h.clone()
	next.attrs = append(next.attrs, attrs...)
	return next
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	next := h.clone()
	if name != "" {
		next.groups = append(next.groups, name)
	}
	return next
}

func (h *PrettyHandler) clone() *PrettyHandler {
	next := *h
	next.attrs = append([]slog.Attr(nil), h.attrs...)
	next.groups = append([]string(nil), h.groups...)
	return &next
}

func (h *PrettyHandler) appendAttr(line *strings.Builder, groups []string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	if attr.Value.Kind() == slog.KindGroup {
		nextGroups := append(groups, attr.Key)
		for _, grouped := range attr.Value.Group() {
			h.appendAttr(line, nextGroups, grouped)
		}
		return
	}

	key := attr.Key
	if len(groups) > 0 {
		parts := append([]string(nil), groups...)
		parts = append(parts, key)
		key = strings.Join(parts, ".")
	}
	if key == "" {
		return
	}

	line.WriteByte(' ')
	line.WriteString(cyan)
	line.WriteString(key)
	line.WriteString(reset)
	line.WriteString("=")
	line.WriteString(magenta)
	line.WriteString(formatValue(attr.Value))
	line.WriteString(reset)
}

func levelLabel(level slog.Level) string {
	name := level.String()
	if len(name) < 5 {
		name += strings.Repeat(" ", 5-len(name))
	}
	return levelColor(level) + name + reset
}

func levelColor(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return red
	case level >= slog.LevelWarn:
		return yellow
	case level <= slog.LevelDebug:
		return blue
	default:
		return green
	}
}

func formatValue(value slog.Value) string {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindBool:
		return strconv.FormatBool(value.Bool())
	case slog.KindInt64:
		return strconv.FormatInt(value.Int64(), 10)
	case slog.KindUint64:
		return strconv.FormatUint(value.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.FormatFloat(value.Float64(), 'f', -1, 64)
	case slog.KindDuration:
		return value.Duration().String()
	case slog.KindTime:
		return value.Time().Format(time.RFC3339)
	case slog.KindAny:
		return fmt.Sprint(value.Any())
	default:
		return value.String()
	}
}
