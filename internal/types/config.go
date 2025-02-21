package types

import "github.com/altafino/email-extractor/internal/models"

// Config represents the application configuration
type Config struct {
	// Meta information for the configuration
	Meta struct {
		ID          string `yaml:"id"`
		Name        string `yaml:"name"`
		Description string `yaml:"description,omitempty"`
		Enabled     bool   `yaml:"enabled"`
		Template    string `yaml:"template,omitempty"` // Name of the template to use
	} `yaml:"meta"`

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
		Protocols      struct {
			IMAP struct {
				Enabled      bool `yaml:"enabled"`
				DefaultPort  int  `yaml:"default_port"`
				InsecurePort int  `yaml:"insecure_port"`
				IdleTimeout  int  `yaml:"idle_timeout"`
				BatchSize    int  `yaml:"batch_size"`
			} `yaml:"imap"`
			POP3 struct {
				Enabled             bool   `yaml:"enabled"`
				DefaultPort         int    `yaml:"default_port"`
				InsecurePort        int    `yaml:"insecure_port"`
				DeleteAfterDownload bool   `yaml:"delete_after_download"`
				Server              string `yaml:"server"`
				Username            string `yaml:"username"`
				Password            string `yaml:"password"`
			} `yaml:"pop3"`
		} `yaml:"protocols"`
		Security struct {
			TLS struct {
				Enabled    bool   `yaml:"enabled"`
				MinVersion string `yaml:"min_version"`
				VerifyCert bool   `yaml:"verify_cert"`
				CertFile   string `yaml:"cert_file"`
				KeyFile    string `yaml:"key_file"`
			} `yaml:"tls"`
		} `yaml:"security"`
		Retry struct {
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

	Scheduling struct {
		Enabled         bool   `yaml:"enabled"`
		FrequencyEvery  string `yaml:"frequency_every"` // minute, hour, day, week, month
		FrequencyAmount int    `yaml:"frequency_amount"`
		StartNow        bool   `yaml:"start_now"`
		StartAt         string `yaml:"start_at"` // UTC DateTime
		StopAt          string `yaml:"stop_at"`  // UTC DateTime
	} `yaml:"scheduling"`
}
