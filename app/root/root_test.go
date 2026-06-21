package root

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mikadore/mygosh/app/logging"
	"github.com/stretchr/testify/require"
)

func TestRootOwnsLoggingServiceLifecycle(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "mygosh.log")
	cfg := logging.Config{
		Level: "INFO",
		File:  logPath,
	}

	appRoot, err := New(cfg)
	require.NoError(t, err)
	require.Same(t, appRoot.Audit, appRoot.Logging.Audit())
	require.Same(t, appRoot.Logging.Diagnostics(), slog.Default())

	appRoot.Logging.SetConsoleEnabled(false)
	appRoot.Audit.Info("root log", "component", "test")
	require.NoError(t, appRoot.Shutdown(context.Background()))

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var record map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(string(content))), &record))
	require.Equal(t, "root log", record["msg"])
	require.Equal(t, "test", record["component"])
	require.Equal(t, "audit", record["stream"])
}

func TestRootReturnsLoggingSetupError(t *testing.T) {
	cfg := logging.Config{
		Level: "INFO",
		File:  filepath.Join(t.TempDir(), "missing", "mygosh.log"),
	}

	appRoot, err := New(cfg)

	require.Nil(t, appRoot)
	require.ErrorContains(t, err, "open log file")
}

func TestRootRestoresPreviousDiagnosticLogger(t *testing.T) {
	previous := slog.Default()
	appRoot, err := New(logging.Config{Level: "NONE"})
	require.NoError(t, err)
	require.NotSame(t, previous, slog.Default())

	require.NoError(t, appRoot.Shutdown(context.Background()))
	require.Same(t, previous, slog.Default())
	require.NoError(t, appRoot.Shutdown(context.Background()))
}
