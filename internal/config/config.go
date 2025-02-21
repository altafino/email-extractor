package config

import (
	"os"

	"github.com/altafino/email-extractor/internal/models"
	yaml "gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port         int    `yaml:"port"`
		Host         string `yaml:"host"`
		ReadTimeout  int    `yaml:"read_timeout"`
		WriteTimeout int    `yaml:"write_timeout"`
		IdleTimeout  int    `yaml:"idle_timeout"`
	} `yaml:"server"`

	Email struct {
		DefaultTimeout int `yaml:"default_timeout"`
		RateLimit      int `yaml:"rate_limit"`
		MaxConcurrent  int `yaml:"max_concurrent"`
		Retry          struct {
			MaxAttempts int `yaml:"max_attempts"`
			Delay       int `yaml:"delay"`
		} `yaml:"retry"`
		Attachments models.AttachmentConfig `yaml:"attachments"`
	} `yaml:"email"`

	Security struct {
		AllowedIPs []string `yaml:"allowed_ips"`
		APIKeys    []string `yaml:"api_keys"`
		CORS       struct {
			Enabled        bool     `yaml:"enabled"`
			AllowedOrigins []string `yaml:"allowed_origins"`
			AllowedMethods []string `yaml:"allowed_methods"`
		} `yaml:"cors"`
	} `yaml:"security"`

	Logging struct {
		Level           string `yaml:"level"`
		Format          string `yaml:"format"`
		Output          string `yaml:"output"`
		FilePath        string `yaml:"file_path"`
		IncludeCaller   bool   `yaml:"include_caller"`
		RedactSensitive bool   `yaml:"redact_sensitive"`
	} `yaml:"logging"`

	Monitoring struct {
		MetricsEnabled  bool   `yaml:"metrics_enabled"`
		MetricsPath     string `yaml:"metrics_path"`
		HealthCheckPath string `yaml:"health_check_path"`
		Tracing         struct {
			Enabled  bool   `yaml:"enabled"`
			Exporter string `yaml:"exporter"`
			Endpoint string `yaml:"endpoint"`
		} `yaml:"tracing"`
	} `yaml:"monitoring"`
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
