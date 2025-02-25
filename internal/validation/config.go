package validation

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

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

	if err := validateScheduling(cfg); err != nil {
		return fmt.Errorf("scheduling validation failed: %w", err)
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

	// Validate tracking configuration
	if err := validateTracking(cfg); err != nil {
		return fmt.Errorf("tracking validation failed: %w", err)
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

func validateTracking(cfg *types.Config) error {
	if !cfg.Email.Tracking.Enabled {
		return nil // Skip validation if tracking is disabled
	}

	switch cfg.Email.Tracking.StorageType {
	case "file", "database":
		// Valid storage types
	default:
		return fmt.Errorf("email.tracking.storage_type must be 'file' or 'database'")
	}

	if cfg.Email.Tracking.StorageType == "file" {
		if cfg.Email.Tracking.StoragePath == "" {
			return fmt.Errorf("email.tracking.storage_path is required when storage_type is 'file'")
		}
		if !filepath.IsAbs(cfg.Email.Tracking.StoragePath) {
			return fmt.Errorf("email.tracking.storage_path must be absolute")
		}
	}

	if cfg.Email.Tracking.RetentionDays <= 0 {
		return fmt.Errorf("email.tracking.retention_days must be positive")
	}

	switch cfg.Email.Tracking.TrackingFormat {
	case "json", "csv":
		// Valid formats
	default:
		return fmt.Errorf("email.tracking.tracking_format must be 'json' or 'csv'")
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

func validateScheduling(cfg *types.Config) error {
	if !cfg.Scheduling.Enabled {
		return nil // Skip validation if scheduling is disabled
	}

	// Validate frequency_every
	validFrequencies := map[string]bool{
		"minute": true,
		"hour":   true,
		"day":    true,
		"week":   true,
		"month":  true,
	}

	if !validFrequencies[cfg.Scheduling.FrequencyEvery] {
		return fmt.Errorf("scheduling.frequency_every must be one of: minute, hour, day, week, month")
	}

	// Validate frequency_amount
	if cfg.Scheduling.FrequencyAmount < 1 {
		return fmt.Errorf("scheduling.frequency_amount must be greater than 0")
	}

	// Validate start and stop times if provided
	if !cfg.Scheduling.StartNow {
		if cfg.Scheduling.StartAt == "" {
			return fmt.Errorf("scheduling.start_at is required when start_now is false")
		}
		if _, err := time.Parse(time.RFC3339, cfg.Scheduling.StartAt); err != nil {
			return fmt.Errorf("scheduling.start_at must be in RFC3339 format (e.g., 2006-01-02T15:04:05Z)")
		}
	}

	if cfg.Scheduling.StopAt != "" {
		stopAt, err := time.Parse(time.RFC3339, cfg.Scheduling.StopAt)
		if err != nil {
			return fmt.Errorf("scheduling.stop_at must be in RFC3339 format (e.g., 2006-01-02T15:04:05Z)")
		}

		// If start_at is provided, validate stop_at is after start_at
		if cfg.Scheduling.StartAt != "" {
			startAt, _ := time.Parse(time.RFC3339, cfg.Scheduling.StartAt)
			if stopAt.Before(startAt) {
				return fmt.Errorf("scheduling.stop_at must be after start_at")
			}
		}

		// If start_now is true, validate stop_at is in the future
		if cfg.Scheduling.StartNow {
			if stopAt.Before(time.Now().UTC()) {
				return fmt.Errorf("scheduling.stop_at must be in the future when start_now is true")
			}
		}
	}

	// Additional frequency-specific validations
	switch cfg.Scheduling.FrequencyEvery {
	case "minute":
		if cfg.Scheduling.FrequencyAmount > 60 {
			return fmt.Errorf("scheduling.frequency_amount must not exceed 60 for minute frequency")
		}
	case "hour":
		if cfg.Scheduling.FrequencyAmount > 24 {
			return fmt.Errorf("scheduling.frequency_amount must not exceed 24 for hour frequency")
		}
	case "day":
		if cfg.Scheduling.FrequencyAmount > 31 {
			return fmt.Errorf("scheduling.frequency_amount must not exceed 31 for day frequency")
		}
	case "week":
		if cfg.Scheduling.FrequencyAmount > 52 {
			return fmt.Errorf("scheduling.frequency_amount must not exceed 52 for week frequency")
		}
	case "month":
		if cfg.Scheduling.FrequencyAmount > 12 {
			return fmt.Errorf("scheduling.frequency_amount must not exceed 12 for month frequency")
		}
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
