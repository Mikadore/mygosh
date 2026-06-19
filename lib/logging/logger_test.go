package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/stretchr/testify/require"
)

func TestNewWithOutputFormatsTextAndDerivedAttributes(t *testing.T) {
	var output bytes.Buffer
	logger := newWithOutput(settings.LogSettings{Level: "INFO"}, &output)

	logger.With("command", "client").Info("connected", "addr", "localhost:42022")

	logged := output.String()
	require.Contains(t, logged, "connected")
	require.Contains(t, logged, "command=client")
	require.Contains(t, logged, "addr=localhost:42022")
}

func TestNewWithOutputFormatsJSON(t *testing.T) {
	var output bytes.Buffer
	logger := newWithOutput(settings.LogSettings{Level: "INFO", JSON: true}, &output)

	logger.Info("connected", "addr", "localhost:42022")

	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	require.Equal(t, "info", record["level"])
	require.Equal(t, "connected", record["msg"])
	require.Equal(t, "localhost:42022", record["addr"])
	require.NotEmpty(t, record["time"])
}

func TestNewWithOutputFiltersBelowConfiguredLevel(t *testing.T) {
	var output bytes.Buffer
	logger := newWithOutput(settings.LogSettings{Level: "WARN"}, &output)

	logger.Info("hidden")
	logger.Warn("visible")

	logged := output.String()
	require.NotContains(t, logged, "hidden")
	require.Contains(t, logged, "visible")
}

func TestNewWithOutputPreservesFatalThreshold(t *testing.T) {
	var output bytes.Buffer
	logger := newWithOutput(settings.LogSettings{Level: "FATAL"}, &output)

	logger.Error("hidden")
	logger.Log(context.Background(), slog.Level(12), "visible")

	logged := output.String()
	require.NotContains(t, logged, "hidden")
	require.Contains(t, logged, "visible")
}

func TestNewWithOutputDisablesEmptyAndNoneLevels(t *testing.T) {
	for _, level := range []string{"", "NONE", " none "} {
		t.Run(strings.TrimSpace(level), func(t *testing.T) {
			var output bytes.Buffer
			logger := newWithOutput(settings.LogSettings{Level: level}, &output)

			logger.Error("hidden")

			require.Empty(t, output.String())
		})
	}
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
