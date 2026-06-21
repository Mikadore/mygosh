package config

import (
	"strings"

	"github.com/Mikadore/mygosh/app/logging"
	"github.com/rotisserie/eris"
	"github.com/spf13/viper"
)

const DefaultClientFile = "mygosh-client.toml"

type Client struct {
	ConfigFile string           `mapstructure:"-"`
	Connection ClientConnection `mapstructure:"connection"`
	Identity   ClientIdentity   `mapstructure:"identity"`
	Trust      ClientTrust      `mapstructure:"trust"`
	Log        logging.Config   `mapstructure:"log"`
}

type ClientConnection struct {
	DefaultPort int `mapstructure:"default_port"`
}

type ClientIdentity struct {
	PrivateKey string `mapstructure:"private_key"`
}

type ClientTrust struct {
	KnownHosts string `mapstructure:"known_hosts"`
}

func LoadClient(path string, verbosity int) (Client, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultClientFile
	}

	reader := viper.New()
	reader.SetConfigFile(path)
	reader.SetConfigType("toml")
	reader.SetDefault("connection.default_port", 42022)
	reader.SetDefault("identity.private_key", "~/.mygosh/id_ed25519")
	reader.SetDefault("trust.known_hosts", "~/.mygosh/known_hosts")
	setLogDefaults(reader)

	if err := reader.ReadInConfig(); err != nil {
		return Client{}, eris.Wrapf(err, "read client config file %s", path)
	}

	var cfg Client
	if err := reader.UnmarshalExact(&cfg); err != nil {
		return Client{}, eris.Wrap(err, "decode client config")
	}
	cfg.ConfigFile = path
	cfg.Identity.PrivateKey = strings.TrimSpace(cfg.Identity.PrivateKey)
	cfg.Trust.KnownHosts = strings.TrimSpace(cfg.Trust.KnownHosts)

	logConfig, err := logging.NormalizeConfig(cfg.Log, verbosity)
	if err != nil {
		return Client{}, err
	}
	cfg.Log = logConfig
	if err := cfg.Validate(); err != nil {
		return Client{}, err
	}
	return cfg, nil
}

func (c Client) Validate() error {
	if c.Connection.DefaultPort < 1 || c.Connection.DefaultPort > 65535 {
		return eris.Errorf("connection.default_port must be between 1 and 65535, got %d", c.Connection.DefaultPort)
	}
	if strings.TrimSpace(c.Identity.PrivateKey) == "" {
		return eris.New("identity.private_key must not be empty")
	}
	if strings.TrimSpace(c.Trust.KnownHosts) == "" {
		return eris.New("trust.known_hosts must not be empty")
	}
	return c.Log.Validate()
}
