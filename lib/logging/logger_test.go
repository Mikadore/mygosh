package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/stretchr/testify/require"
)

type writeCloser struct {
	io.Writer
	closeCount int
}

func (w *writeCloser) Close() error {
	w.closeCount++
	return nil
}

func TestServiceFormatsConsoleTextAndDerivedAttributes(t *testing.T) {
	var console bytes.Buffer
	service := newService(settings.LogSettings{Level: "INFO"}, &console, nil, nil)

	service.Logger().With("command", "client").Info("connected", "addr", "localhost:42022")

	logged := console.String()
	require.Contains(t, logged, "connected")
	require.Contains(t, logged, "command=client")
	require.Contains(t, logged, "addr=localhost:42022")
}

func TestServiceFormatsConsoleJSON(t *testing.T) {
	var console bytes.Buffer
	service := newService(settings.LogSettings{Level: "INFO", JSON: true}, &console, nil, nil)

	service.Logger().Info("connected", "addr", "localhost:42022")

	var record map[string]any
	require.NoError(t, json.Unmarshal(console.Bytes(), &record))
	require.Equal(t, "info", record["level"])
	require.Equal(t, "connected", record["msg"])
	require.Equal(t, "localhost:42022", record["addr"])
	require.NotEmpty(t, record["time"])
}

func TestServiceFiltersBelowConfiguredLevel(t *testing.T) {
	var console bytes.Buffer
	service := newService(settings.LogSettings{Level: "WARN"}, &console, nil, nil)

	service.Logger().Info("hidden")
	service.Logger().Warn("visible")

	logged := console.String()
	require.NotContains(t, logged, "hidden")
	require.Contains(t, logged, "visible")
}

func TestServicePreservesFatalThreshold(t *testing.T) {
	var console bytes.Buffer
	service := newService(settings.LogSettings{Level: "FATAL"}, &console, nil, nil)

	service.Logger().Error("hidden")
	service.Logger().Log(context.Background(), slog.Level(12), "visible")

	logged := console.String()
	require.NotContains(t, logged, "hidden")
	require.Contains(t, logged, "visible")
}

func TestServiceDisablesEmptyAndNoneLevels(t *testing.T) {
	for _, level := range []string{"", "NONE", " none "} {
		t.Run(strings.TrimSpace(level), func(t *testing.T) {
			var console bytes.Buffer
			var file bytes.Buffer
			service := newService(settings.LogSettings{Level: level}, &console, &file, nil)

			service.Logger().Error("hidden")

			require.Empty(t, console.String())
			require.Empty(t, file.String())
		})
	}
}

func TestConsoleToggleDoesNotDisableFileHandler(t *testing.T) {
	var console bytes.Buffer
	var file bytes.Buffer
	service := newService(settings.LogSettings{Level: "INFO"}, &console, &file, nil)
	logger := service.Logger().With("command", "client")

	logger.Info("before")
	service.SetConsoleEnabled(false)
	logger.Info("file only")
	service.SetConsoleEnabled(true)
	logger.Info("after")

	consoleLog := console.String()
	require.Contains(t, consoleLog, "before")
	require.NotContains(t, consoleLog, "file only")
	require.Contains(t, consoleLog, "after")

	fileRecords := decodeJSONLines(t, file.String())
	require.Len(t, fileRecords, 3)
	require.Equal(t, "before", fileRecords[0]["msg"])
	require.Equal(t, "file only", fileRecords[1]["msg"])
	require.Equal(t, "after", fileRecords[2]["msg"])
	require.Equal(t, "client", fileRecords[1]["command"])
}

func TestConsoleToggleIsSafeDuringLogging(t *testing.T) {
	service := newService(settings.LogSettings{Level: "INFO"}, io.Discard, io.Discard, nil)

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for i := 0; i < 1000; i++ {
			service.SetConsoleEnabled(i%2 == 0)
		}
	}()
	go func() {
		defer wait.Done()
		for i := 0; i < 1000; i++ {
			service.Logger().Info("concurrent log", "sequence", i)
		}
	}()
	wait.Wait()
}

func TestNewServiceAppendsJSONToConfiguredFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mygosh.log")
	require.NoError(t, os.WriteFile(path, nil, 0o644))

	first, err := NewService(settings.LogSettings{Level: "INFO", File: path})
	require.NoError(t, err)
	first.SetConsoleEnabled(false)
	first.Logger().Info("first", "value", 1)
	require.NoError(t, first.Close())

	second, err := NewService(settings.LogSettings{Level: "INFO", File: path})
	require.NoError(t, err)
	second.SetConsoleEnabled(false)
	second.Logger().Info("second", "value", 2)
	require.NoError(t, second.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	records := decodeJSONLines(t, string(content))
	require.Len(t, records, 2)
	require.Equal(t, "first", records[0]["msg"])
	require.Equal(t, "second", records[1]["msg"])

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestNewServiceReturnsLogFileOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "mygosh.log")

	service, err := NewService(settings.LogSettings{Level: "INFO", File: path})

	require.Nil(t, service)
	require.ErrorContains(t, err, "open log file")
}

func TestNewServiceDoesNotOpenFileWhenLoggingIsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "mygosh.log")

	service, err := NewService(settings.LogSettings{Level: "NONE", File: path})

	require.NoError(t, err)
	require.NotNil(t, service)
	require.NoError(t, service.Close())
}

func TestServiceCloseClosesFileOnce(t *testing.T) {
	closer := &writeCloser{Writer: io.Discard}
	service := newService(settings.LogSettings{Level: "INFO"}, io.Discard, closer, closer)

	require.NoError(t, service.Close())
	require.NoError(t, service.Close())
	require.Equal(t, 1, closer.closeCount)
}

func TestResolveReturnsProvidedLoggerAndNopForNil(t *testing.T) {
	provided := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	require.Same(t, provided, Resolve(provided))
	require.NotNil(t, Resolve(nil))
	require.Same(t, Nop(), Resolve(nil))
	require.NotPanics(t, func() {
		Resolve(nil).Info("discarded")
	})
}

func decodeJSONLines(t *testing.T, content string) []map[string]any {
	t.Helper()

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		records = append(records, record)
	}
	return records
}
