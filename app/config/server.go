package config

import (
	"net"
	"strconv"
	"strings"

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
	Identity      ServerIdentity      `mapstructure:"identity"`
	Authorization ServerAuthorization `mapstructure:"authorization"`
	Log           logging.Config      `mapstructure:"log"`
}

type ServerListen struct {
	Address string `mapstructure:"address"`
}

type ServerIdentity struct {
	HostKey string `mapstructure:"host_key"`
}

type ServerAuthorization struct {
	AuthorizedKeys []string `mapstructure:"authorized_keys"`
}

func LoadServer(path string, verbosity int) (Server, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultServerFile
	}

	reader := viper.New()
	reader.SetConfigFile(path)
	reader.SetConfigType("toml")
	reader.SetDefault("listen.address", "localhost:42022")
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
	if len(s.Authorization.AuthorizedKeys) == 0 {
		return eris.New("authorization.authorized_keys must not be empty")
	}
	for _, path := range s.Authorization.AuthorizedKeys {
		if path == "" {
			return eris.New("authorization.authorized_keys entries must not be empty")
		}
	}
	return s.Log.Validate()
}
