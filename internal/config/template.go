package config

import (
	"fmt"
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

	return template, nil
}

// ApplyTemplate merges a template with a configuration
func ApplyTemplate(cfg *types.Config, templateName string) error {
	if globalTemplates == nil {
		return fmt.Errorf("templates not initialized")
	}

	template, exists := globalTemplates.templates[templateName]
	if !exists {
		return fmt.Errorf("template %s not found", templateName)
	}

	// Create a copy of the template
	base := &types.Config{}
	if err := mergo.Merge(base, template); err != nil {
		return fmt.Errorf("failed to copy template: %w", err)
	}

	// Merge configuration over template
	if err := mergo.Merge(base, cfg, mergo.WithOverride); err != nil {
		return fmt.Errorf("failed to merge config with template: %w", err)
	}

	// Copy merged result back to original config
	*cfg = *base
	return nil
}
