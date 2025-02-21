package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/altafino/email-extractor/internal/app"
	"github.com/altafino/email-extractor/internal/config"
	applogger "github.com/altafino/email-extractor/internal/logger"
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
)

func main() {
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
	// Create a default config for initial logging
	defaultConfig := &types.Config{}
	defaultConfig.Logging.Level = "info"
	defaultConfig.Logging.Format = "text"
	logger = applogger.Setup(defaultConfig)
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

	// Update logger with loaded configuration
	if configID != "" {
		if cfg, err := config.GetConfig(configID); err == nil {
			logger = applogger.Setup(cfg)
			slog.SetDefault(logger)
		}
	} else {
		// Use first enabled config for logging settings
		configs := config.GetEnabledConfigs()
		if len(configs) > 0 {
			logger = applogger.Setup(configs[0])
			slog.SetDefault(logger)
		}
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

func run(cmd *cobra.Command, args []string) error {
	// Create and start application
	app, err := app.New(logger, "./config", configID)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	// Start the application
	if err := app.Start(); err != nil {
		return fmt.Errorf("failed to start application: %w", err)
	}

	// Wait for shutdown signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop
	logger.Info("received shutdown signal", "signal", sig)

	// Gracefully shutdown the application
	app.Stop()
	return nil
}
