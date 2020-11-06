package config

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// CFG - Global access to configuration
var CFG *viper.Viper

func init() {
	CFG = loadConfig()
}

// LoadConfig - Returns a viper instance
func loadConfig() *viper.Viper {
	conf := viper.New()
	conf.SetConfigName("config")
	conf.SetConfigType("yaml")
	conf.AddConfigPath(".")
	conf.AddConfigPath("~/.aws-es-proxy")
	conf.AddConfigPath("/etc/aws-es-proxy")

	if err := conf.ReadInConfig(); err != nil {
		logrus.Fatalln("Unable to read from configuration file")
	}

	return conf
}
