package settings

import (
	"net"
	"strconv"
	"strings"

	"github.com/rotisserie/eris"
	"github.com/spf13/viper"
)

const ConfigFile = "mygosh.toml"

type Settings struct {
	ConfigFile string       `mapstructure:"-"`
	Verbosity  int          `mapstructure:"-"`
	Core       CoreSettings `mapstructure:"core"`
	Log        LogSettings  `mapstructure:"log"`
}

type CoreSettings struct {
	Host  string `mapstructure:"host"`
	Port  int    `mapstructure:"port"`
	Shell string `mapstructure:"shell"`
}

type LogSettings struct {
	Level string `mapstructure:"level"`
	JSON  bool   `mapstructure:"json"`
	File  string `mapstructure:"file"`
}

func Load(verbosity int) (Settings, error) {
	reader := viper.New()
	reader.SetConfigFile(ConfigFile)
	reader.SetConfigType("toml")
	reader.SetDefault("core.host", "localhost")
	reader.SetDefault("core.port", 42022)
	reader.SetDefault("core.shell", "/bin/sh")
	reader.SetDefault("log.level", "")
	reader.SetDefault("log.json", false)
	reader.SetDefault("log.file", "")

	if err := reader.ReadInConfig(); err != nil {
		return Settings{}, eris.Wrapf(err, "read config file %s", ConfigFile)
	}

	var cfg Settings
	if err := reader.Unmarshal(&cfg); err != nil {
		return Settings{}, eris.Wrap(err, "decode config")
	}

	cfg.ConfigFile = ConfigFile
	cfg.Verbosity = verbosity
	cfg.Core.Host = strings.TrimSpace(cfg.Core.Host)
	cfg.Log.Level = strings.ToUpper(strings.TrimSpace(cfg.Log.Level))
	cfg.Log.File = strings.TrimSpace(cfg.Log.File)
	if cfg.Log.Level == "WARNING" {
		cfg.Log.Level = "WARN"
	}
	if verbosity == 1 {
		cfg.Log.Level = "INFO"
	}
	if verbosity >= 2 {
		cfg.Log.Level = "DEBUG"
	}

	if err := cfg.Validate(); err != nil {
		return Settings{}, err
	}
	return cfg, nil
}

func (s Settings) ListenAddress() string {
	return net.JoinHostPort(s.Core.Host, strconv.Itoa(s.Core.Port))
}

func (s Settings) Validate() error {
	if strings.TrimSpace(s.Core.Host) == "" {
		return eris.New("core.host must not be empty")
	}
	if s.Core.Port < 1 || s.Core.Port > 65535 {
		return eris.Errorf("core.port must be between 1 and 65535, got %d", s.Core.Port)
	}
	if strings.TrimSpace(s.Core.Shell) == "" {
		return eris.New("core.shell must not be empty")
	}
	switch s.Log.Level {
	case "", "NONE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL":
		return nil
	default:
		return eris.Errorf("log.level must be one of DEBUG, INFO, WARN, ERROR, FATAL, NONE; got %q", s.Log.Level)
	}
}
