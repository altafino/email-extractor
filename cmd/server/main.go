package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/altafino/email-extractor/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	logLevel    string
	logFormat   string
	serverPort  int
	metricsPort int
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
	cobra.OnInitialize(initConfig)

	// Command line flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config/config.yaml)")
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
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in default locations
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/email-extractor")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Read environment variables
	viper.SetEnvPrefix("EMAIL_EXTRACTOR")
	viper.AutomaticEnv()

	// Read config
	if err := viper.ReadInConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
		os.Exit(1)
	}
}

func setupLogger(cfg *config.Config) *slog.Logger {
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
	// Load configuration
	cfg := &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Setup logger
	logger := setupLogger(cfg)
	slog.SetDefault(logger)

	logger.Info("starting email-extractor service",
		"version", "1.0.0",
		"config_file", viper.ConfigFileUsed(),
		"port", cfg.Server.Port,
	)

	// TODO: Initialize and start the API server
	// This will be implemented in the next step when we create the API package

	// Block until signal received
	select {}
}
