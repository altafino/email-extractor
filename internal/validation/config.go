package validation

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/altafino/email-extractor/internal/types"
)

// ValidateConfig performs validation on a single configuration
func ValidateConfig(cfg *types.Config) error {
	if err := validateMeta(cfg); err != nil {
		return fmt.Errorf("meta validation failed: %w", err)
	}

	if err := validateServer(cfg); err != nil {
		return fmt.Errorf("server validation failed: %w", err)
	}

	if err := validateEmail(cfg); err != nil {
		return fmt.Errorf("email validation failed: %w", err)
	}

	if err := validateSecurity(cfg); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	if err := validateLogging(cfg); err != nil {
		return fmt.Errorf("logging validation failed: %w", err)
	}

	return nil
}

func validateMeta(cfg *types.Config) error {
	if cfg.Meta.ID == "" {
		return fmt.Errorf("meta.id is required")
	}

	if !isValidID(cfg.Meta.ID) {
		return fmt.Errorf("meta.id contains invalid characters (use only alphanumeric, dash, underscore)")
	}

	if cfg.Meta.Name == "" {
		return fmt.Errorf("meta.name is required")
	}

	return nil
}

func validateServer(cfg *types.Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}

	if cfg.Server.ReadTimeout <= 0 {
		return fmt.Errorf("server.read_timeout must be positive")
	}

	if cfg.Server.WriteTimeout <= 0 {
		return fmt.Errorf("server.write_timeout must be positive")
	}

	return nil
}

func validateEmail(cfg *types.Config) error {
	if cfg.Email.DefaultTimeout <= 0 {
		return fmt.Errorf("email.default_timeout must be positive")
	}

	if cfg.Email.RateLimit <= 0 {
		return fmt.Errorf("email.rate_limit must be positive")
	}

	if cfg.Email.MaxConcurrent <= 0 {
		return fmt.Errorf("email.max_concurrent must be positive")
	}

	// Validate attachments configuration
	if err := validateAttachments(cfg); err != nil {
		return fmt.Errorf("attachments validation failed: %w", err)
	}

	return nil
}

func validateAttachments(cfg *types.Config) error {
	if len(cfg.Email.Attachments.AllowedTypes) == 0 {
		return fmt.Errorf("email.attachments.allowed_types must not be empty")
	}

	for _, ext := range cfg.Email.Attachments.AllowedTypes {
		if !strings.HasPrefix(ext, ".") {
			return fmt.Errorf("email.attachments.allowed_types: extension %q must start with dot", ext)
		}
	}

	if cfg.Email.Attachments.MaxSize <= 0 {
		return fmt.Errorf("email.attachments.max_size must be positive")
	}

	if cfg.Email.Attachments.StoragePath == "" {
		return fmt.Errorf("email.attachments.storage_path is required")
	}

	if !filepath.IsAbs(cfg.Email.Attachments.StoragePath) {
		return fmt.Errorf("email.attachments.storage_path must be absolute")
	}

	return nil
}

func validateSecurity(cfg *types.Config) error {
	if len(cfg.Security.APIKeys) == 0 {
		return fmt.Errorf("security.api_keys must not be empty")
	}

	for _, key := range cfg.Security.APIKeys {
		if len(key) < 16 {
			return fmt.Errorf("security.api_keys: key length must be at least 16 characters")
		}
	}

	if cfg.Security.CORS.Enabled {
		if len(cfg.Security.CORS.AllowedOrigins) == 0 {
			return fmt.Errorf("security.cors.allowed_origins must not be empty when CORS is enabled")
		}
		if len(cfg.Security.CORS.AllowedMethods) == 0 {
			return fmt.Errorf("security.cors.allowed_methods must not be empty when CORS is enabled")
		}
	}

	return nil
}

func validateLogging(cfg *types.Config) error {
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLevels[cfg.Logging.Level] {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error")
	}

	validFormats := map[string]bool{
		"text": true,
		"json": true,
	}

	if !validFormats[cfg.Logging.Format] {
		return fmt.Errorf("logging.format must be one of: text, json")
	}

	validOutputs := map[string]bool{
		"stdout": true,
		"file":   true,
	}

	if !validOutputs[cfg.Logging.Output] {
		return fmt.Errorf("logging.output must be one of: stdout, file")
	}

	if cfg.Logging.Output == "file" && cfg.Logging.FilePath == "" {
		return fmt.Errorf("logging.file_path is required when output is 'file'")
	}

	return nil
}

func isValidID(id string) bool {
	for _, r := range id {
		if !isValidIDChar(r) {
			return false
		}
	}
	return true
}

func isValidIDChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' ||
		r == '_'
}
