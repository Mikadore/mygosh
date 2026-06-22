package config

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Mikadore/mygosh/app/logging"
	"github.com/rotisserie/eris"
	"github.com/spf13/viper"
)

const DefaultServerFile = "mygosh-server.toml"

var defaultAuthorizedKeys = []string{
	"~/.mygosh/authorized_keys",
	"~/.ssh/authorized_keys",
}

type Server struct {
	ConfigFile    string              `mapstructure:"-"`
	Listen        ServerListen        `mapstructure:"listen"`
	Daemon        ServerDaemon        `mapstructure:"daemon"`
	Identity      ServerIdentity      `mapstructure:"identity"`
	Authorization ServerAuthorization `mapstructure:"authorization"`
	Log           logging.Config      `mapstructure:"log"`
}

type ServerListen struct {
	Address string `mapstructure:"address"`
}

type ServerDaemon struct {
	MaxConnections      int           `mapstructure:"max_connections"`
	MaxConnectionsPerIP int           `mapstructure:"max_connections_per_ip"`
	ShutdownTimeout     time.Duration `mapstructure:"shutdown_timeout"`
}

type ServerIdentity struct {
	HostKey string `mapstructure:"host_key"`
}

type ServerAuthorization struct {
	AuthorizedKeys []string           `mapstructure:"authorized_keys"`
	Permissions    *ServerPermissions `mapstructure:"permissions"`
}

type ServerPermissions struct {
	AllowShell         bool     `mapstructure:"allow_shell"`
	AllowExec          bool     `mapstructure:"allow_exec"`
	AllowPTY           bool     `mapstructure:"allow_pty"`
	AllowedEnvironment []string `mapstructure:"allowed_environment"`
	ForcedCommand      string   `mapstructure:"forced_command"`
}

func LoadServer(path string, verbosity int) (Server, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultServerFile
	}

	reader := viper.New()
	reader.SetConfigFile(path)
	reader.SetConfigType("toml")
	reader.SetDefault("listen.address", "localhost:42022")
	reader.SetDefault("daemon.max_connections", 32)
	reader.SetDefault("daemon.max_connections_per_ip", 4)
	reader.SetDefault("daemon.shutdown_timeout", "5s")
	reader.SetDefault("identity.host_key", "~/.mygosh/host_ed25519")
	reader.SetDefault("authorization.authorized_keys", defaultAuthorizedKeys)
	setLogDefaults(reader)

	if err := reader.ReadInConfig(); err != nil {
		return Server{}, eris.Wrapf(err, "read server config file %s", path)
	}

	var cfg Server
	if err := reader.UnmarshalExact(&cfg); err != nil {
		return Server{}, eris.Wrap(err, "decode server config")
	}
	cfg.ConfigFile = path
	cfg.Listen.Address = strings.TrimSpace(cfg.Listen.Address)
	cfg.Identity.HostKey = strings.TrimSpace(cfg.Identity.HostKey)
	for i := range cfg.Authorization.AuthorizedKeys {
		cfg.Authorization.AuthorizedKeys[i] = strings.TrimSpace(cfg.Authorization.AuthorizedKeys[i])
	}
	if cfg.Authorization.Permissions != nil {
		cfg.Authorization.Permissions.ForcedCommand = strings.TrimSpace(cfg.Authorization.Permissions.ForcedCommand)
		for i := range cfg.Authorization.Permissions.AllowedEnvironment {
			cfg.Authorization.Permissions.AllowedEnvironment[i] = strings.TrimSpace(cfg.Authorization.Permissions.AllowedEnvironment[i])
		}
	}

	logConfig, err := logging.NormalizeConfig(cfg.Log, verbosity)
	if err != nil {
		return Server{}, err
	}
	cfg.Log = logConfig
	if err := cfg.Validate(); err != nil {
		return Server{}, err
	}
	return cfg, nil
}

func (s Server) Validate() error {
	host, portText, err := net.SplitHostPort(s.Listen.Address)
	if err != nil {
		return eris.Wrap(err, "listen.address must be a host:port address")
	}
	if strings.TrimSpace(host) == "" {
		return eris.New("listen.address host must not be empty")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return eris.Errorf("listen.address port must be between 1 and 65535, got %q", portText)
	}
	if strings.TrimSpace(s.Identity.HostKey) == "" {
		return eris.New("identity.host_key must not be empty")
	}
	if s.Daemon.MaxConnections < 1 || s.Daemon.MaxConnections > 4096 {
		return eris.New("daemon.max_connections must be between 1 and 4096")
	}
	if s.Daemon.MaxConnectionsPerIP < 1 || s.Daemon.MaxConnectionsPerIP > s.Daemon.MaxConnections {
		return eris.New("daemon.max_connections_per_ip must be between 1 and daemon.max_connections")
	}
	if s.Daemon.ShutdownTimeout <= 0 || s.Daemon.ShutdownTimeout > 5*time.Minute {
		return eris.New("daemon.shutdown_timeout must be greater than zero and at most 5m")
	}
	if len(s.Authorization.AuthorizedKeys) == 0 {
		return eris.New("authorization.authorized_keys must not be empty")
	}
	for _, path := range s.Authorization.AuthorizedKeys {
		if path == "" {
			return eris.New("authorization.authorized_keys entries must not be empty")
		}
	}
	if s.Authorization.Permissions == nil {
		return eris.New("authorization.permissions must be configured explicitly")
	}
	if err := s.Authorization.Permissions.Validate(); err != nil {
		return err
	}
	return s.Log.Validate()
}

func (p ServerPermissions) Validate() error {
	if p.AllowPTY && !p.AllowShell && !p.AllowExec {
		return eris.New("authorization.permissions.allow_pty requires shell or exec permission")
	}
	if p.ForcedCommand != "" && !p.AllowShell && !p.AllowExec {
		return eris.New("authorization.permissions.forced_command requires shell or exec permission")
	}
	if strings.ContainsRune(p.ForcedCommand, '\x00') {
		return eris.New("authorization.permissions.forced_command contains NUL")
	}
	if len(p.ForcedCommand) > 24<<10 {
		return eris.New("authorization.permissions.forced_command exceeds maximum size")
	}
	if len(p.AllowedEnvironment) > 128 {
		return eris.New("authorization.permissions.allowed_environment has too many entries")
	}
	seen := make(map[string]struct{}, len(p.AllowedEnvironment))
	for _, name := range p.AllowedEnvironment {
		if name == "" || strings.ContainsAny(name, "=\x00") || len(name) > 256 {
			return eris.Errorf("authorization.permissions.allowed_environment contains invalid name %q", name)
		}
		if _, ok := seen[name]; ok {
			return eris.Errorf("authorization.permissions.allowed_environment contains duplicate %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}
