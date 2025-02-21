package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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
		if err := os.MkdirAll(cfg.Email.Attachments.StoragePath, 0755); err != nil {
			return fmt.Errorf("failed to create storage path for config %s: %w", cfg.Meta.ID, err)
		}

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

	// Expand environment variables in the config file
	expandedData := os.ExpandEnv(string(data))

	config := &types.Config{}
	if err := yaml.Unmarshal([]byte(expandedData), config); err != nil {
		return nil, err
	}

	// Log the POP3 configuration after environment variable expansion
	if config.Email.Protocols.POP3.Enabled {
		logger.Debug("POP3 configuration loaded",
			"server", config.Email.Protocols.POP3.Server,
			"username", config.Email.Protocols.POP3.Username,
			"port", config.Email.Protocols.POP3.DefaultPort,
			"tls_enabled", config.Email.Security.TLS.Enabled,
		)
	}

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
