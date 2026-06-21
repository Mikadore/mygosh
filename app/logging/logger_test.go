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

func TestServiceSeparatesAuditAndDiagnosticStreams(t *testing.T) {
	var console bytes.Buffer
	service := newService(Config{Level: "INFO"}, &console, nil, nil)

	service.Audit().With("command", "server").Info("accepted")
	service.Diagnostics().With("component", "session").Info("activated")

	logged := console.String()
	require.Contains(t, logged, "stream=audit")
	require.Contains(t, logged, "stream=diagnostic")
	require.Contains(t, logged, "command=server")
	require.Contains(t, logged, "component=session")
}

func TestServiceFormatsConsoleJSON(t *testing.T) {
	var console bytes.Buffer
	service := newService(Config{Level: "INFO", JSON: true}, &console, nil, nil)

	service.Audit().Info("connected", "addr", "localhost:42022")

	var record map[string]any
	require.NoError(t, json.Unmarshal(console.Bytes(), &record))
	require.Equal(t, "info", record["level"])
	require.Equal(t, "connected", record["msg"])
	require.Equal(t, "audit", record["stream"])
	require.Equal(t, "localhost:42022", record["addr"])
}

func TestServiceFiltersBelowConfiguredLevel(t *testing.T) {
	var console bytes.Buffer
	service := newService(Config{Level: "WARN"}, &console, nil, nil)

	service.Diagnostics().Info("hidden")
	service.Diagnostics().Warn("visible")

	require.NotContains(t, console.String(), "hidden")
	require.Contains(t, console.String(), "visible")
}

func TestServicePreservesFatalThreshold(t *testing.T) {
	var console bytes.Buffer
	service := newService(Config{Level: "FATAL"}, &console, nil, nil)

	service.Audit().Error("hidden")
	service.Audit().Log(context.Background(), slog.Level(12), "visible")

	require.NotContains(t, console.String(), "hidden")
	require.Contains(t, console.String(), "visible")
}

func TestServiceDisablesEmptyAndNoneLevels(t *testing.T) {
	for _, level := range []string{"", "NONE", " none "} {
		t.Run(strings.TrimSpace(level), func(t *testing.T) {
			var console bytes.Buffer
			var file bytes.Buffer
			service := newService(Config{Level: level}, &console, &file, nil)

			service.Audit().Error("hidden")
			service.Diagnostics().Error("also hidden")

			require.Empty(t, console.String())
			require.Empty(t, file.String())
		})
	}
}

func TestConsoleToggleDoesNotDisableFileHandler(t *testing.T) {
	var console bytes.Buffer
	var file bytes.Buffer
	service := newService(Config{Level: "INFO"}, &console, &file, nil)

	service.Audit().Info("before")
	service.SetConsoleEnabled(false)
	service.Diagnostics().Info("file only")
	service.SetConsoleEnabled(true)
	service.Audit().Info("after")

	require.Contains(t, console.String(), "before")
	require.NotContains(t, console.String(), "file only")
	require.Contains(t, console.String(), "after")

	fileRecords := decodeJSONLines(t, file.String())
	require.Len(t, fileRecords, 3)
	require.Equal(t, "diagnostic", fileRecords[1]["stream"])
}

func TestConsoleToggleIsSafeDuringLogging(t *testing.T) {
	service := newService(Config{Level: "INFO"}, io.Discard, io.Discard, nil)

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
			service.Diagnostics().Info("concurrent log", "sequence", i)
		}
	}()
	wait.Wait()
}

func TestNewServiceAppendsJSONToConfiguredFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mygosh.log")
	require.NoError(t, os.WriteFile(path, nil, 0o644))

	first, err := NewService(Config{Level: "INFO", File: path})
	require.NoError(t, err)
	first.SetConsoleEnabled(false)
	first.Audit().Info("first")
	require.NoError(t, first.Close())

	second, err := NewService(Config{Level: "INFO", File: path})
	require.NoError(t, err)
	second.SetConsoleEnabled(false)
	second.Diagnostics().Info("second")
	require.NoError(t, second.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	records := decodeJSONLines(t, string(content))
	require.Len(t, records, 2)
	require.Equal(t, "audit", records[0]["stream"])
	require.Equal(t, "diagnostic", records[1]["stream"])

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestNewServiceReturnsLogFileOpenError(t *testing.T) {
	service, err := NewService(Config{
		Level: "INFO",
		File:  filepath.Join(t.TempDir(), "missing", "mygosh.log"),
	})

	require.Nil(t, service)
	require.ErrorContains(t, err, "open log file")
}

func TestNewServiceDoesNotOpenFileWhenLoggingIsDisabled(t *testing.T) {
	service, err := NewService(Config{
		Level: "NONE",
		File:  filepath.Join(t.TempDir(), "missing", "mygosh.log"),
	})

	require.NoError(t, err)
	require.NoError(t, service.Close())
}

func TestServiceCloseClosesFileOnce(t *testing.T) {
	closer := &writeCloser{Writer: io.Discard}
	service := newService(Config{Level: "INFO"}, io.Discard, closer, closer)

	require.NoError(t, service.Close())
	require.NoError(t, service.Close())
	require.Equal(t, 1, closer.closeCount)
}

func TestNormalizeConfigAppliesVerbosityAndValidatesLevel(t *testing.T) {
	cfg, err := NormalizeConfig(Config{Level: " none ", File: " log.json "}, 2)
	require.NoError(t, err)
	require.Equal(t, "DEBUG", cfg.Level)
	require.Equal(t, "log.json", cfg.File)

	_, err = NormalizeConfig(Config{Level: "verbose"}, 0)
	require.Error(t, err)
}

func TestNilServiceReturnsNopLoggers(t *testing.T) {
	var service *Service
	require.NotPanics(t, func() {
		service.Audit().Info("discarded audit")
		service.Diagnostics().Info("discarded diagnostic")
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
