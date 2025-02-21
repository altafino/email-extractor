package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/altafino/email-extractor/internal/config"
	"github.com/altafino/email-extractor/internal/scheduler"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	logLevel    string
	logFormat   string
	serverPort  int
	metricsPort int
	configID    string
	logger      *slog.Logger
	sched       *scheduler.Scheduler
)

func main() {
	defer cleanup()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "email-extractor",
	Short: "Email attachment extraction service",
	Long: `A service that downloads emails using POP3 or IMAP settings and extracts attachments, 
storing them in a specified location.`,
	RunE: run,
}

func init() {
	// Setup default logger until we load config
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cobra.OnInitialize(initConfig)

	// Command line flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config-dir", "", "config directory (default is ./config)")
	rootCmd.PersistentFlags().StringVar(&configID, "config-id", "", "specific config ID to use")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "override logging level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "", "override logging format (text, json)")
	rootCmd.PersistentFlags().IntVar(&serverPort, "port", 0, "override server port")
	rootCmd.PersistentFlags().IntVar(&metricsPort, "metrics-port", 0, "override metrics port")

	// Bind flags to viper
	viper.BindPFlag("logging.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("logging.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("server.port", rootCmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("monitoring.metrics_port", rootCmd.PersistentFlags().Lookup("metrics-port"))
}

func initConfig() {
	configDir := "./config"
	if cfgFile != "" {
		configDir = cfgFile
	}

	if err := config.LoadConfigs(configDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configs: %v\n", err)
		os.Exit(1)
	}

	// List available configurations
	configs := config.ListConfigs()
	if len(configs) == 0 {
		fmt.Fprintf(os.Stderr, "No configurations found in %s\n", configDir)
		os.Exit(1)
	}

	logger.Info("loaded configurations",
		"count", len(configs),
		"enabled", len(config.GetEnabledConfigs()),
	)

	for _, cfg := range configs {
		logger.Info("configuration loaded",
			"id", cfg.Meta.ID,
			"name", cfg.Meta.Name,
			"enabled", cfg.Meta.Enabled,
		)
	}
}

func setupLogger(cfg *types.Config) *slog.Logger {
	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.Logging.IncludeCaller,
	}

	var handler slog.Handler
	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

func run(cmd *cobra.Command, args []string) error {
	var configs []*types.Config

	if configID != "" {
		// Use specific configuration
		cfg, err := config.GetConfig(configID)
		if err != nil {
			return fmt.Errorf("failed to get config %s: %w", configID, err)
		}
		configs = []*types.Config{cfg}
	} else {
		// Use all enabled configurations
		configs = config.GetEnabledConfigs()
	}

	// Start configuration watcher
	watcher, err := config.StartWatcher("./config", logger)
	if err != nil {
		return fmt.Errorf("failed to start config watcher: %w", err)
	}
	defer watcher.Stop()

	// Channel for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start services for initial configurations
	for _, cfg := range configs {
		if err := startServices(cfg); err != nil {
			return err
		}
	}

	// Watch for configuration changes
	go func() {
		for range watcher.ReloadChan() {
			logger.Info("reloading services due to configuration change")

			// Get updated configurations
			var newConfigs []*types.Config
			if configID != "" {
				cfg, err := config.GetConfig(configID)
				if err != nil {
					logger.Error("failed to get updated config",
						"id", configID,
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
				if err := updateServices(cfg); err != nil {
					logger.Error("failed to update services",
						"config_id", cfg.Meta.ID,
						"error", err,
					)
				}
			}
		}
	}()

	// Wait for shutdown signal
	<-stop
	logger.Info("shutting down services")
	return nil
}

func startServices(cfg *types.Config) error {
	// Setup logger for this configuration
	logger := setupLogger(cfg)

	// Initialize scheduler if not already initialized
	if sched == nil {
		sched = scheduler.NewScheduler(logger)
		sched.Start()
	}

	// Update scheduler with configuration
	if err := sched.UpdateJob(cfg); err != nil {
		logger.Error("failed to update scheduler",
			"error", err,
			"id", cfg.Meta.ID,
		)
		return err
	}

	logger.Info("starting service with configuration",
		"id", cfg.Meta.ID,
		"name", cfg.Meta.Name,
		"port", cfg.Server.Port,
	)

	return nil
}

func updateServices(cfg *types.Config) error {
	// Update scheduler with new configuration
	if err := sched.UpdateJob(cfg); err != nil {
		logger.Error("failed to update scheduler",
			"error", err,
			"id", cfg.Meta.ID,
		)
		return err
	}
	return nil
}

func cleanup() {
	if sched != nil {
		sched.Stop()
	}
}
