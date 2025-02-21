package app

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/altafino/email-extractor/internal/config"
	"github.com/altafino/email-extractor/internal/scheduler"
	"github.com/altafino/email-extractor/internal/types"
)

// App represents the main application
type App struct {
	logger    *slog.Logger
	scheduler *scheduler.Scheduler
	configs   []*types.Config
	configID  string
	watcher   *config.ConfigWatcher
	wg        sync.WaitGroup
}

// New creates a new application instance
func New(logger *slog.Logger, configDir string, configID string) (*App, error) {
	app := &App{
		logger:   logger,
		configID: configID,
	}

	// Load initial configurations
	if err := config.LoadConfigs(configDir); err != nil {
		return nil, fmt.Errorf("failed to load configs: %w", err)
	}

	// Get configurations based on configID
	if configID != "" {
		cfg, err := config.GetConfig(configID)
		if err != nil {
			return nil, fmt.Errorf("failed to get config %s: %w", configID, err)
		}
		app.configs = []*types.Config{cfg}
	} else {
		app.configs = config.GetEnabledConfigs()
	}

	// Initialize scheduler
	app.scheduler = scheduler.NewScheduler(logger)

	return app, nil
}

// Start starts all application services
func (a *App) Start() error {
	// Start configuration watcher
	watcher, err := config.StartWatcher("./config", a.logger)
	if err != nil {
		return fmt.Errorf("failed to start config watcher: %w", err)
	}
	a.watcher = watcher

	// Start scheduler
	a.scheduler.Start()

	// Start services for initial configurations
	for _, cfg := range a.configs {
		if err := a.startServices(cfg); err != nil {
			return err
		}
	}

	// Watch for configuration changes
	a.wg.Add(1)
	go a.watchConfigs()

	return nil
}

// Stop gracefully stops all application services
func (a *App) Stop() {
	if a.watcher != nil {
		a.watcher.Stop()
	}
	if a.scheduler != nil {
		a.scheduler.Stop()
	}
	a.wg.Wait()
}

func (a *App) startServices(cfg *types.Config) error {
	// Update scheduler with configuration
	if err := a.scheduler.UpdateJob(cfg); err != nil {
		a.logger.Error("failed to update scheduler",
			"error", err,
			"id", cfg.Meta.ID,
		)
		return err
	}

	a.logger.Info("started services for configuration",
		"id", cfg.Meta.ID,
		"name", cfg.Meta.Name,
	)

	return nil
}

func (a *App) watchConfigs() {
	defer a.wg.Done()

	for range a.watcher.ReloadChan() {
		a.logger.Info("reloading services due to configuration change")

		// Get updated configurations
		var newConfigs []*types.Config
		if a.configID != "" {
			cfg, err := config.GetConfig(a.configID)
			if err != nil {
				a.logger.Error("failed to get updated config",
					"id", a.configID,
					"error", err,
				)
				continue
			}
			newConfigs = []*types.Config{cfg}
		} else {
			newConfigs = config.GetEnabledConfigs()
		}

		// Update services with new configurations
		for _, cfg := range newConfigs {
			if err := a.startServices(cfg); err != nil {
				a.logger.Error("failed to update services",
					"config_id", cfg.Meta.ID,
					"error", err,
				)
			}
		}
	}
}
