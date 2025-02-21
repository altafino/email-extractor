package config

import (
	"os"

	"github.com/altafino/email-extractor/internal/models"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port int    `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"server"`

	Email struct {
		DefaultTimeout int                     `yaml:"default_timeout"`
		RateLimit      int                     `yaml:"rate_limit"`
		Attachments    models.AttachmentConfig `yaml:"attachments"`
	} `yaml:"email"`

	Security struct {
		AllowedIPs []string `yaml:"allowed_ips"`
		APIKeys    []string `yaml:"api_keys"`
	} `yaml:"security"`
}

var globalConfig *Config

func Load(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return err
	}

	// Ensure storage path exists
	if err := os.MkdirAll(config.Email.Attachments.StoragePath, 0755); err != nil {
		return err
	}

	globalConfig = config
	return nil
}

func Get() *Config {
	return globalConfig
}
