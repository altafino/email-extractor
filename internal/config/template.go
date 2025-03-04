package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"dario.cat/mergo"
	"github.com/altafino/email-extractor/internal/types"
	yaml "gopkg.in/yaml.v3"
)

type TemplateManager struct {
	templates map[string]*types.Config
}

var globalTemplates *TemplateManager

// LoadTemplates loads all template files from the templates directory
func LoadTemplates(templatesDir string) error {
	tm := &TemplateManager{
		templates: make(map[string]*types.Config),
	}

	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		return fmt.Errorf("failed to read templates directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		templatePath := filepath.Join(templatesDir, entry.Name())
		template, err := loadTemplate(templatePath)
		if err != nil {
			return fmt.Errorf("failed to load template %s: %w", entry.Name(), err)
		}

		templateName := strings.TrimSuffix(entry.Name(), ".yaml")
		tm.templates[templateName] = template
	}

	globalTemplates = tm
	return nil
}

func loadTemplate(path string) (*types.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	template := &types.Config{}
	if err := yaml.Unmarshal(data, template); err != nil {
		return nil, err
	}

	// Ensure template has correct naming pattern
	if template.Email.Attachments.NamingPattern == "" || template.Email.Attachments.NamingPattern == "_" {
		template.Email.Attachments.NamingPattern = "${unixtime}_${filename}"
		logger.Debug("set default naming pattern in template",
			"template_path", path,
			"pattern", template.Email.Attachments.NamingPattern)
	}

	return template, nil
}

// ApplyTemplate merges a template with a configuration
func ApplyTemplate(cfg *types.Config, templateName string) error {
	if logger == nil {
		logger = slog.Default()
	}

	logger.Debug("applying template",
		"template_name", templateName,
		"config_id", cfg.Meta.ID)

	template, exists := globalTemplates.templates[templateName]
	if !exists {
		return fmt.Errorf("template %s not found", templateName)
	}

	// Store original values that should not be overridden
	originalValues := map[string]interface{}{
		"scheduling.start_now": cfg.Scheduling.StartNow,
		"scheduling.enabled":   cfg.Scheduling.Enabled,
		"imap.enabled":         cfg.Email.Protocols.IMAP.Enabled,
		"pop3.enabled":         cfg.Email.Protocols.POP3.Enabled,
		"api_keys":             cfg.Security.APIKeys,
	}

	logger.Debug("original values before template merge",
		"start_now", cfg.Scheduling.StartNow,
		"scheduling_enabled", cfg.Scheduling.Enabled,
		"imap_enabled", cfg.Email.Protocols.IMAP.Enabled,
		"pop3_enabled", cfg.Email.Protocols.POP3.Enabled,
		"api_keys_count", len(cfg.Security.APIKeys))

	// Create a copy of the config
	merged := &types.Config{}

	// First, copy the template as the base
	if err := mergo.Merge(merged, template); err != nil {
		return fmt.Errorf("failed to copy template: %w", err)
	}

	// Then merge the user config over it with override
	if err := mergo.Merge(merged, cfg, mergo.WithOverride); err != nil {
		return fmt.Errorf("failed to merge config: %w", err)
	}

	// Restore original values that should not be overridden by the template
	merged.Scheduling.StartNow = originalValues["scheduling.start_now"].(bool)
	merged.Scheduling.Enabled = originalValues["scheduling.enabled"].(bool)
	merged.Email.Protocols.IMAP.Enabled = originalValues["imap.enabled"].(bool)
	merged.Email.Protocols.POP3.Enabled = originalValues["pop3.enabled"].(bool)

	// Only restore API keys if they were not empty in the original config
	if len(originalValues["api_keys"].([]string)) > 0 {
		merged.Security.APIKeys = originalValues["api_keys"].([]string)
	}

	// Copy merged result back to original config
	*cfg = *merged

	logger.Debug("after template merge",
		"final_start_now", cfg.Scheduling.StartNow,
		"final_scheduling_enabled", cfg.Scheduling.Enabled,
		"final_imap_enabled", cfg.Email.Protocols.IMAP.Enabled,
		"final_pop3_enabled", cfg.Email.Protocols.POP3.Enabled,
		"final_api_keys_count", len(cfg.Security.APIKeys))

	return nil
}
