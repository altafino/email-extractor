package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/altafino/email-extractor/internal/types"
	"github.com/imdario/mergo"
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
		template.Email.Attachments.NamingPattern = "${timestamp}_${filename}.${ext}"
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
		"before_pattern", cfg.Email.Attachments.NamingPattern)

	template, exists := globalTemplates.templates[templateName]
	if !exists {
		return fmt.Errorf("template %s not found", templateName)
	}

	logger.Debug("template content",
		"template_name", templateName,
		"template_pattern", template.Email.Attachments.NamingPattern)

	// Create a copy of the config
	merged := &types.Config{}

	// First, copy the config
	if err := mergo.Merge(merged, cfg); err != nil {
		return fmt.Errorf("failed to copy config: %w", err)
	}

	// Then merge the template over it, but only for zero/empty values
	if err := mergo.Merge(merged, template, mergo.WithOverrideEmptySlice); err != nil {
		return fmt.Errorf("failed to merge template: %w", err)
	}

	// Copy merged result back to original config
	*cfg = *merged

	logger.Debug("after template merge",
		"final_pattern", cfg.Email.Attachments.NamingPattern,
		"full_attachments_config", cfg.Email.Attachments)

	return nil
}
