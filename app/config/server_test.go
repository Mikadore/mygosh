package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadServerUsesDefaultsAndConfiguredAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte("[listen]\naddress = \"0.0.0.0:42022\"\n"), 0o600))

	cfg, err := LoadServer(path, 0)
	require.NoError(t, err)
	require.Equal(t, path, cfg.ConfigFile)
	require.Equal(t, "0.0.0.0:42022", cfg.Listen.Address)
	require.Equal(t, "~/.mygosh/host_ed25519", cfg.Identity.HostKey)
	require.Equal(t, defaultAuthorizedKeys, cfg.Authorization.AuthorizedKeys)
}

func TestLoadServerTrimsAuthorizationPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[authorization]
authorized_keys = ["  ~/.mygosh/authorized_keys  "]

[log]
file = "  mygosh.log  "
`), 0o600))

	cfg, err := LoadServer(path, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"~/.mygosh/authorized_keys"}, cfg.Authorization.AuthorizedKeys)
	require.Equal(t, "mygosh.log", cfg.Log.File)
}

func TestLoadServerRejectsClientOnlyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte("[connection]\ndefault_port = 42022\n"), 0o600))

	_, err := LoadServer(path, 0)
	require.ErrorContains(t, err, "decode server config")
}
