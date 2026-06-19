package root

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/stretchr/testify/require"
)

func TestRootOwnsLoggingServiceLifecycle(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "mygosh.log")
	cfg := settings.Settings{
		Log: settings.LogSettings{
			Level: "INFO",
			File:  logPath,
		},
	}

	appRoot, err := New(cfg)
	require.NoError(t, err)
	require.Same(t, appRoot.Logger, appRoot.Logging.Logger())

	appRoot.Logging.SetConsoleEnabled(false)
	appRoot.Logger.Info("root log", "component", "test")
	require.NoError(t, appRoot.Shutdown(context.Background()))

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var record map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(string(content))), &record))
	require.Equal(t, "root log", record["msg"])
	require.Equal(t, "test", record["component"])
}

func TestRootReturnsLoggingSetupError(t *testing.T) {
	cfg := settings.Settings{
		Log: settings.LogSettings{
			Level: "INFO",
			File:  filepath.Join(t.TempDir(), "missing", "mygosh.log"),
		},
	}

	appRoot, err := New(cfg)

	require.Nil(t, appRoot)
	require.ErrorContains(t, err, "open log file")
}
