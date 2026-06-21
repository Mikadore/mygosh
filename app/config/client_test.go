package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadClientUsesDefaultsAndTrimsPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[identity]
private_key = "  ~/.mygosh/custom_id  "

[trust]
known_hosts = "  ~/.mygosh/custom_hosts  "
`), 0o600))

	cfg, err := LoadClient(path, 0)
	require.NoError(t, err)
	require.Equal(t, path, cfg.ConfigFile)
	require.Equal(t, 42022, cfg.Connection.DefaultPort)
	require.Equal(t, "~/.mygosh/custom_id", cfg.Identity.PrivateKey)
	require.Equal(t, "~/.mygosh/custom_hosts", cfg.Trust.KnownHosts)
}

func TestLoadClientAppliesVerbosityToLogging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")
	require.NoError(t, os.WriteFile(path, []byte("[log]\nlevel = \"NONE\"\n"), 0o600))

	cfg, err := LoadClient(path, 2)
	require.NoError(t, err)
	require.Equal(t, "DEBUG", cfg.Log.Level)
}

func TestLoadClientRejectsUnknownServerFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")
	require.NoError(t, os.WriteFile(path, []byte("[listen]\naddress = \"localhost:42022\"\n"), 0o600))

	_, err := LoadClient(path, 0)
	require.ErrorContains(t, err, "decode client config")
}
