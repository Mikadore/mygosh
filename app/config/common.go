package config

import "github.com/spf13/viper"

func setLogDefaults(reader *viper.Viper) {
	reader.SetDefault("log.level", "")
	reader.SetDefault("log.json", false)
	reader.SetDefault("log.file", "")
}
