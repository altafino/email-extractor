package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/types"
	yaml "gopkg.in/yaml.v3"
)

// ConfigStore manages multiple configurations
type ConfigStore struct {
	configs map[string]*types.Config // map[id]*Config
}

var (
	globalStore *ConfigStore
	logger      *slog.Logger
)

// InitLogger sets up the logger for the config package
func InitLogger(l *slog.Logger) {
	logger = l
}

// LoadConfigs loads all configuration files from the specified directory
func LoadConfigs(configDir string) error {
	if logger == nil {
		logger = slog.Default()
	}

	store := &ConfigStore{
		configs: make(map[string]*types.Config),
	}

	// Load templates first
	templatesDir := filepath.Join(configDir, "templates")
	if err := LoadTemplates(templatesDir); err != nil {
		return fmt.Errorf("failed to load templates: %w", err)
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		return fmt.Errorf("failed to read config directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".config.yaml") {
			continue
		}

		configPath := filepath.Join(configDir, entry.Name())
		cfg, err := loadSingleConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config %s: %w", entry.Name(), err)
		}

		if cfg.Meta.ID == "" {
			return fmt.Errorf("config %s missing required meta.id field", entry.Name())
		}

		if _, exists := store.configs[cfg.Meta.ID]; exists {
			return fmt.Errorf("duplicate config ID %s in %s", cfg.Meta.ID, entry.Name())
		}

		// Ensure storage path exists for each config
		//if err := os.MkdirAll(cfg.Email.Attachments.StoragePath, 0755); err != nil {
		//	// return fmt.Errorf("failed to create storage path for config %s: %w", cfg.Meta.ID, err)
		//}

		// Apply template if specified
		if cfg.Meta.Template != "" {
			if err := ApplyTemplate(cfg, cfg.Meta.Template); err != nil {
				return fmt.Errorf("failed to apply template to config %s: %w", entry.Name(), err)
			}
		}

		store.configs[cfg.Meta.ID] = cfg

		logger.Debug("loaded configuration",
			"id", cfg.Meta.ID,
			"pop3_server", cfg.Email.Protocols.POP3.Server,
			"pop3_username", cfg.Email.Protocols.POP3.Username,
			"imap_server", cfg.Email.Protocols.IMAP.Server,
			"imap_username", cfg.Email.Protocols.IMAP.Username,
		)
	}

	globalStore = store
	return nil
}

func loadSingleConfig(path string) (*types.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Log raw config data
	logger.Debug("raw config data before processing",
		"path", path,
		"content", string(data))

	// First, parse the YAML without any environment variable expansion
	config := &types.Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Now handle environment variable expansion for specific fields that should support it
	// but not for fields that might contain $ as part of their value

	// For example, expand environment variables in server addresses, usernames, etc.
	// but not in attachment paths that might contain ${YYYY} patterns

	// We can selectively expand environment variables for specific fields
	if strings.HasPrefix(config.Email.Protocols.POP3.Server, "${") {
		config.Email.Protocols.POP3.Server = os.ExpandEnv(config.Email.Protocols.POP3.Server)
	}

	if strings.HasPrefix(config.Email.Protocols.POP3.Username, "${") {
		config.Email.Protocols.POP3.Username = os.ExpandEnv(config.Email.Protocols.POP3.Username)
	}

	if strings.HasPrefix(config.Email.Protocols.POP3.Password, "${") {
		config.Email.Protocols.POP3.Password = os.ExpandEnv(config.Email.Protocols.POP3.Password)
	}

	if strings.HasPrefix(config.Email.Protocols.IMAP.Server, "${") {
		config.Email.Protocols.IMAP.Server = os.ExpandEnv(config.Email.Protocols.IMAP.Server)
	}

	if strings.HasPrefix(config.Email.Protocols.IMAP.Username, "${") {
		config.Email.Protocols.IMAP.Username = os.ExpandEnv(config.Email.Protocols.IMAP.Username)
	}

	if strings.HasPrefix(config.Email.Protocols.IMAP.Password, "${") {
		config.Email.Protocols.IMAP.Password = os.ExpandEnv(config.Email.Protocols.IMAP.Password)
	}

	// Do NOT expand environment variables in the storage path
	// This preserves ${YYYY}, ${MM}, etc. patterns

	// Set default naming pattern if not specified
	if config.Email.Attachments.NamingPattern == "" || config.Email.Attachments.NamingPattern == "_" {
		config.Email.Attachments.NamingPattern = "${unixtime}_${filename}"
		logger.Debug("set default naming pattern",
			"pattern", config.Email.Attachments.NamingPattern)
	}

	// Validate storage path
	if config.Email.Attachments.StoragePath == "" {
		logger.Warn("storage path is empty, setting default",
			"default", "/tmp/email-attachments")
		config.Email.Attachments.StoragePath = "/tmp/email-attachments"
	}

	// Validate IMAP date filter if enabled
	if config.Email.Protocols.IMAP.DateFilter.Enabled {
		// Validate From date if provided
		if config.Email.Protocols.IMAP.DateFilter.From != "" {
			_, err := time.Parse(time.RFC3339, config.Email.Protocols.IMAP.DateFilter.From)
			if err != nil {
				logger.Warn("invalid IMAP from date format, will use default at runtime",
					"from", config.Email.Protocols.IMAP.DateFilter.From,
					"error", err)
			}
		}

		// Validate To date if provided
		if config.Email.Protocols.IMAP.DateFilter.To != "" {
			_, err := time.Parse(time.RFC3339, config.Email.Protocols.IMAP.DateFilter.To)
			if err != nil {
				logger.Warn("invalid IMAP to date format, will use default at runtime",
					"to", config.Email.Protocols.IMAP.DateFilter.To,
					"error", err)
			}
		}

		logger.Debug("IMAP date filtering enabled",
			"from", config.Email.Protocols.IMAP.DateFilter.From,
			"to", config.Email.Protocols.IMAP.DateFilter.To)
	}

	// Log detailed attachment configuration
	logger.Debug("attachment configuration after processing",
		"storage_path", config.Email.Attachments.StoragePath,
		"naming_pattern", config.Email.Attachments.NamingPattern,
		"preserve_structure", config.Email.Attachments.PreserveStructure,
		"sanitize_filenames", config.Email.Attachments.SanitizeFilenames)

	return config, nil
}

// GetConfig retrieves a configuration by ID
func GetConfig(id string) (*types.Config, error) {
	if globalStore == nil {
		return nil, fmt.Errorf("config store not initialized")
	}

	cfg, exists := globalStore.configs[id]
	if !exists {
		return nil, fmt.Errorf("config with ID %s not found", id)
	}

	return cfg, nil
}

// ListConfigs returns a list of all available configurations
func ListConfigs() []*types.Config {
	if globalStore == nil {
		return nil
	}

	configs := make([]*types.Config, 0, len(globalStore.configs))
	for _, cfg := range globalStore.configs {
		configs = append(configs, cfg)
	}
	return configs
}

// GetEnabledConfigs returns only enabled configurations
func GetEnabledConfigs() []*types.Config {
	if globalStore == nil {
		return nil
	}

	configs := make([]*types.Config, 0)
	for _, cfg := range globalStore.configs {
		if cfg.Meta.Enabled {
			configs = append(configs, cfg)
		}
	}
	return configs
}

// tryFixDateFormat attempts to fix common date format issues
func tryFixDateFormat(dateStr string) string {
	// Check if it's a valid RFC3339 date already
	if _, err := time.Parse(time.RFC3339, dateStr); err == nil {
		return dateStr
	}
	
	// Split the date part from the time part
	parts := strings.Split(dateStr, "T")
	if len(parts) != 2 {
		return dateStr // Can't fix if it doesn't have the expected T separator
	}
	
	datePart := parts[0]
	timePart := parts[1]
	
	// Split the date into components
	dateComponents := strings.Split(datePart, "-")
	if len(dateComponents) != 3 {
		return dateStr // Can't fix if it doesn't have 3 components
	}
	
	year := dateComponents[0]
	month := dateComponents[1]
	day := dateComponents[2]
	
	// Check if month is greater than 12 (invalid)
	monthInt, err := strconv.Atoi(month)
	if err != nil || monthInt <= 12 {
		// Month is valid or not a number, no need to swap
		return dateStr
	}
	
	// Month is invalid, try to swap month and day
	dayInt, err := strconv.Atoi(day)
	if err != nil || dayInt > 31 {
		// Day is invalid or not a number, can't fix
		return dateStr
	}
	
	// Swap month and day if day is a valid month number
	if dayInt <= 12 {
		// Create the fixed date string
		fixedDateStr := fmt.Sprintf("%s-%02d-%02dT%s", year, dayInt, monthInt, timePart)
		return fixedDateStr
	}
	
	return dateStr // Couldn't fix
}

// InitStore initializes the configuration store with the given directory
func InitStore(configDir string) error {
	// Check if the directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return fmt.Errorf("config directory does not exist: %s", configDir)
	}

	// Check if templates directory exists
	templatesDir := filepath.Join(configDir, "templates")
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		return fmt.Errorf("templates directory does not exist: %s", templatesDir)
	}

	// Initialize the store
	store := &ConfigStore{
		configs: make(map[string]*types.Config),
	}

	// Load templates
	if err := LoadTemplates(templatesDir); err != nil {
		return fmt.Errorf("failed to load templates: %w", err)
	}

	// Load configurations
	if err := LoadConfigs(configDir); err != nil {
		return fmt.Errorf("failed to load configurations: %w", err)
	}

	globalStore = store
	return nil
}

// SetConfig sets a configuration with the given ID
func SetConfig(id string, cfg *types.Config) {
	if globalStore == nil {
		globalStore = &ConfigStore{
			configs: make(map[string]*types.Config),
		}
	}
	globalStore.configs[id] = cfg
}
