package settings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadDefaultsCoreHostToLocalhost(t *testing.T) {
	t.Chdir(t.TempDir())

	config := []byte("[core]\nport = 42022\n")
	err := os.WriteFile(filepath.Join(".", ConfigFile), config, 0o644)
	require.NoError(t, err)

	cfg, err := Load(0)
	require.NoError(t, err)
	require.Equal(t, "localhost", cfg.Core.Host)
	require.Equal(t, "localhost:42022", cfg.ListenAddress())
}

func TestLoadTrimsLogFilePath(t *testing.T) {
	t.Chdir(t.TempDir())

	config := []byte("[core]\nport = 42022\n[log]\nfile = \"  mygosh.log  \"\n")
	err := os.WriteFile(filepath.Join(".", ConfigFile), config, 0o644)
	require.NoError(t, err)

	cfg, err := Load(0)
	require.NoError(t, err)
	require.Equal(t, "mygosh.log", cfg.Log.File)
}

func TestListenAddressUsesConfiguredHost(t *testing.T) {
	cfg := Settings{
		Core: CoreSettings{
			Host: "0.0.0.0",
			Port: 42022,
		},
	}

	require.NoError(t, cfg.Validate())
	require.Equal(t, "0.0.0.0:42022", cfg.ListenAddress())
}
