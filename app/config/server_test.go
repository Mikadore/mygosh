package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadServerUsesDefaultsAndConfiguredAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[listen]
address = "0.0.0.0:42022"

[authorization.permissions]
allow_shell = false
allow_exec = false
allow_pty = false
`), 0o600))

	cfg, err := LoadServer(path, 0)
	require.NoError(t, err)
	require.Equal(t, path, cfg.ConfigFile)
	require.Equal(t, "0.0.0.0:42022", cfg.Listen.Address)
	require.Equal(t, "~/.mygosh/host_ed25519", cfg.Identity.HostKey)
	require.Equal(t, defaultAuthorizedKeys, cfg.Authorization.AuthorizedKeys)
	require.Equal(t, 32, cfg.Daemon.MaxConnections)
	require.Equal(t, 4, cfg.Daemon.MaxConnectionsPerIP)
	require.Equal(t, 5*time.Second, cfg.Daemon.ShutdownTimeout)
	require.NotNil(t, cfg.Authorization.Permissions)
}

func TestLoadServerTrimsAuthorizationPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[authorization]
authorized_keys = ["  ~/.mygosh/authorized_keys  "]

[authorization.permissions]
allow_exec = true
allowed_environment = ["  LANG  "]

[log]
file = "  mygosh.log  "
`), 0o600))

	cfg, err := LoadServer(path, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"~/.mygosh/authorized_keys"}, cfg.Authorization.AuthorizedKeys)
	require.Equal(t, []string{"LANG"}, cfg.Authorization.Permissions.AllowedEnvironment)
	require.Equal(t, "mygosh.log", cfg.Log.File)
}

func TestLoadServerRejectsClientOnlyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte("[connection]\ndefault_port = 42022\n"), 0o600))

	_, err := LoadServer(path, 0)
	require.ErrorContains(t, err, "decode server config")
}

func TestLoadServerRequiresExplicitPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte("[listen]\naddress = \"localhost:42022\"\n"), 0o600))

	_, err := LoadServer(path, 0)
	require.ErrorContains(t, err, "authorization.permissions")
}

func TestLoadServerRejectsInvalidDaemonAndPermissionLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[daemon]
max_connections = 2
max_connections_per_ip = 3

[authorization.permissions]
allow_pty = true
`), 0o600))

	_, err := LoadServer(path, 0)
	require.Error(t, err)
}
