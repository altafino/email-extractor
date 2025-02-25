package types

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
				Enabled      bool     `yaml:"enabled"`
				DefaultPort  int      `yaml:"default_port"`
				InsecurePort int      `yaml:"insecure_port"`
				IdleTimeout  int      `yaml:"idle_timeout"`
				BatchSize    int      `yaml:"batch_size"`
				Server       string   `yaml:"server"`
				Username     string   `yaml:"username"`
				Password     string   `yaml:"password"`
				Folders      []string `yaml:"folders"`
				UseIdle      bool     `yaml:"use_idle"`
				Security     struct {
					TLS struct {
						Enabled    bool   `yaml:"enabled"`
						MinVersion string `yaml:"min_version"`
						VerifyCert bool   `yaml:"verify_cert"`
						CertFile   string `yaml:"cert_file"`
						KeyFile    string `yaml:"key_file"`
					} `yaml:"tls"`
					OAuth2 struct {
						Enabled      bool   `yaml:"enabled"`
						Provider     string `yaml:"provider"`
						ClientID     string `yaml:"client_id"`
						ClientSecret string `yaml:"client_secret"`
					} `yaml:"oauth2"`
				} `yaml:"security"`
			} `yaml:"imap"`
			POP3 struct {
				Enabled             bool   `yaml:"enabled"`
				DefaultPort         int    `yaml:"default_port"`
				InsecurePort        int    `yaml:"insecure_port"`
				DeleteAfterDownload bool   `yaml:"delete_after_download"`
				Server              string `yaml:"server"`
				Username            string `yaml:"username"`
				Password            string `yaml:"password"`
				Security            struct {
					TLS struct {
						Enabled    bool   `yaml:"enabled"`
						MinVersion string `yaml:"min_version"`
						VerifyCert bool   `yaml:"verify_cert"`
						CertFile   string `yaml:"cert_file"`
						KeyFile    string `yaml:"key_file"`
					} `yaml:"tls"`
					OAuth2 struct {
						Enabled      bool   `yaml:"enabled"`
						Provider     string `yaml:"provider"`
						ClientID     string `yaml:"client_id"`
						ClientSecret string `yaml:"client_secret"`
					} `yaml:"oauth2"`
				} `yaml:"security"`
			} `yaml:"pop3"`
		} `yaml:"protocols"`
		Retry struct {
			MaxAttempts int `yaml:"max_attempts"`
			Delay       int `yaml:"delay"`
		} `yaml:"retry"`
		Attachments struct {
			AllowedTypes      []string `yaml:"allowed_types"`
			MaxSize           int64    `yaml:"max_size"`
			StoragePath       string   `yaml:"storage_path"`
			NamingPattern     string   `yaml:"naming_pattern"`
			PreserveStructure bool     `yaml:"preserve_structure"`
			SanitizeFilenames bool     `yaml:"sanitize_filenames"`
			HandleDuplicates  string   `yaml:"handle_duplicates"`
		} `yaml:"attachments"`
		Tracking struct {
			Enabled         bool   `yaml:"enabled"`
			StorageType     string `yaml:"storage_type"`     // "file" or "database"
			StoragePath     string `yaml:"storage_path"`     // Path for file-based tracking
			RetentionDays   int    `yaml:"retention_days"`   // How long to keep tracking records
			TrackingFormat  string `yaml:"tracking_format"`  // "json" or "csv"
			TrackDownloaded bool   `yaml:"track_downloaded"` // Whether to track and skip already downloaded emails
		} `yaml:"tracking"`
	} `yaml:"email"`

	Security struct {
		AllowedIPs []string `yaml:"allowed_ips"`
		APIKeys    []string `yaml:"api_keys"`
		CORS       struct {
			Enabled          bool     `yaml:"enabled"`
			AllowedOrigins   []string `yaml:"allowed_origins"`
			AllowedMethods   []string `yaml:"allowed_methods"`
			AllowedHeaders   []string `yaml:"allowed_headers"`
			ExposeHeaders    []string `yaml:"expose_headers"`
			MaxAge           int      `yaml:"max_age"`
			AllowCredentials bool     `yaml:"allow_credentials"`
		} `yaml:"cors"`
		RateLimiting struct {
			Enabled           bool `yaml:"enabled"`
			RequestsPerSecond int  `yaml:"requests_per_second"`
			Burst             int  `yaml:"burst"`
		} `yaml:"rate_limiting"`
	} `yaml:"security"`

	Logging struct {
		Level           string `yaml:"level"`
		Format          string `yaml:"format"`
		Output          string `yaml:"output"`
		FilePath        string `yaml:"file_path"`
		IncludeCaller   bool   `yaml:"include_caller"`
		RedactSensitive bool   `yaml:"redact_sensitive"`
		Rotation        struct {
			Enabled    bool `yaml:"enabled"`
			MaxSize    int  `yaml:"max_size"`
			MaxAge     int  `yaml:"max_age"`
			MaxBackups int  `yaml:"max_backups"`
			Compress   bool `yaml:"compress"`
		} `yaml:"rotation"`
	} `yaml:"logging"`

	Monitoring struct {
		MetricsEnabled  bool   `yaml:"metrics_enabled"`
		MetricsPath     string `yaml:"metrics_path"`
		HealthCheckPath string `yaml:"health_check_path"`
		Tracing         struct {
			Enabled    bool    `yaml:"enabled"`
			Exporter   string  `yaml:"exporter"`
			Endpoint   string  `yaml:"endpoint"`
			SampleRate float64 `yaml:"sample_rate"`
		} `yaml:"tracing"`
		Profiling struct {
			Enabled bool   `yaml:"enabled"`
			Path    string `yaml:"path"`
		} `yaml:"profiling"`
		Alerts struct {
			Enabled   bool `yaml:"enabled"`
			Endpoints []struct {
				Type    string `yaml:"type"`
				Address string `yaml:"address"`
			} `yaml:"endpoints"`
			Thresholds struct {
				ErrorRate        float64 `yaml:"error_rate"`
				ResponseTimeMs   int     `yaml:"response_time_ms"`
				DiskUsagePercent int     `yaml:"disk_usage_percent"`
			} `yaml:"thresholds"`
		} `yaml:"alerts"`
	} `yaml:"monitoring"`

	Scheduling struct {
		Enabled         bool   `yaml:"enabled"`
		FrequencyEvery  string `yaml:"frequency_every"`
		FrequencyAmount int    `yaml:"frequency_amount"`
		StartNow        bool   `yaml:"start_now"`
		StartAt         string `yaml:"start_at"`
		StopAt          string `yaml:"stop_at"`
	} `yaml:"scheduling"`
}
