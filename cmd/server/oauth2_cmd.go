package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/altafino/email-extractor/internal/config"
	"github.com/altafino/email-extractor/internal/oauth2"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/spf13/cobra"
	goauth2 "golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

// CreateOAuth2Command creates and returns the OAuth2 command
func CreateOAuth2Command() *cobra.Command {
	// Create OAuth2 command
	oauth2Cmd := &cobra.Command{
		Use:   "oauth2",
		Short: "OAuth2 token management",
		Long:  `Manage OAuth2 tokens for email accounts`,
	}
	
	// Add generate token command
	generateCmd := &cobra.Command{
		Use:   "generate [config-id]",
		Short: "Generate OAuth2 token",
		Long:  `Generate OAuth2 token for a specific configuration`,
		Args:  cobra.ExactArgs(1),
		Run:   generateOAuth2Token,
	}
	
	// Add list tokens command
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List OAuth2 tokens",
		Long:  `List all stored OAuth2 tokens`,
		Run:   listOAuth2Tokens,
	}
	
	// Add delete token command
	deleteCmd := &cobra.Command{
		Use:   "delete [config-id]",
		Short: "Delete OAuth2 token",
		Long:  `Delete OAuth2 token for a specific configuration`,
		Args:  cobra.ExactArgs(1),
		Run:   deleteOAuth2Token,
	}
	
	// Add commands to OAuth2 command
	oauth2Cmd.AddCommand(generateCmd)
	oauth2Cmd.AddCommand(listCmd)
	oauth2Cmd.AddCommand(deleteCmd)
	
	return oauth2Cmd
}

func generateOAuth2Token(cmd *cobra.Command, args []string) {
	configID := args[0]
	
	// Load configuration
	cfg, err := config.GetConfig(configID)
	if err != nil {
		fmt.Printf("Error: Failed to load configuration: %v\n", err)
		os.Exit(1)
	}
	
	// Check if OAuth2 is enabled
	if !cfg.Email.Protocols.IMAP.Security.OAuth2.Enabled {
		fmt.Printf("Error: OAuth2 is not enabled for configuration %s\n", configID)
		os.Exit(1)
	}
	
	// Get the OAuth2 provider config
	providerName := cfg.Email.Protocols.IMAP.Security.OAuth2.Provider
	oauth2Config, err := oauth2.GetProviderConfig(
		providerName,
		cfg.Email.Protocols.IMAP.Security.OAuth2.ClientID,
		cfg.Email.Protocols.IMAP.Security.OAuth2.ClientSecret,
		"http://localhost:8085/oauth/callback", // Use local redirect URI
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	// Generate authorization URL
	authURL := oauth2Config.AuthCodeURL("state", goauth2.AccessTypeOffline, goauth2.ApprovalForce)
	
	fmt.Printf("Please open the following URL in your browser:\n\n%s\n\n", authURL)
	fmt.Println("Waiting for authentication...")
	
	// Create logger for the OAuth2 server
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	
	// Start the local server and wait for the authorization code
	authCode, err := oauth2.StartLocalServer(context.Background(), logger)
	if err != nil {
		fmt.Printf("Error: Failed to get authorization code: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("Authorization code received, exchanging for token...")
	
	// Exchange authorization code for token
	token, err := oauth2Config.Exchange(context.Background(), authCode)
	if err != nil {
		fmt.Printf("Error: Failed to exchange authorization code for token: %v\n", err)
		os.Exit(1)
	}
	
	// Create token storage directory
	tokenDir := cfg.Email.Protocols.IMAP.Security.OAuth2.TokenStoragePath
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		fmt.Printf("Error: Failed to create token directory: %v\n", err)
		os.Exit(1)
	}
	
	// Create account ID for token storage
	accountID := fmt.Sprintf("%s_%s", cfg.Meta.ID, cfg.Email.Protocols.IMAP.Username)
	
	// Create token manager
	tokenManager, err := oauth2.NewTokenManager(oauth2Config, tokenDir, accountID, logger)
	if err != nil {
		fmt.Printf("Error: Failed to create token manager: %v\n", err)
		os.Exit(1)
	}
	
	// Save token
	if err := tokenManager.SetToken(token); err != nil {
		fmt.Printf("Error: Failed to save token: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("OAuth2 token generated and saved for account %s\n", accountID)
	fmt.Printf("Token expires at: %s\n", token.Expiry.Format("2006-01-02 15:04:05"))
}

func listOAuth2Tokens(cmd *cobra.Command, args []string) {
	// Get all configurations
	configs := config.ListConfigs()
	
	// Create a map to store token directories
	tokenDirs := make(map[string]bool)
	
	// Collect token directories from all configurations
	for _, cfg := range configs {
		if cfg.Email.Protocols.IMAP.Security.OAuth2.Enabled {
			tokenDir := cfg.Email.Protocols.IMAP.Security.OAuth2.TokenStoragePath
			tokenDirs[tokenDir] = true
		}
	}
	
	// Check if we have any token directories
	if len(tokenDirs) == 0 {
		fmt.Println("No OAuth2 tokens found")
		return
	}
	
	// List tokens in each directory
	foundTokens := false
	for tokenDir := range tokenDirs {
		// Check if directory exists
		if _, err := os.Stat(tokenDir); os.IsNotExist(err) {
			continue
		}
		
		// Read directory
		entries, err := os.ReadDir(tokenDir)
		if err != nil {
			fmt.Printf("Failed to read token directory %s: %v\n", tokenDir, err)
			continue
		}
		
		// Print tokens
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				foundTokens = true
				accountID := strings.TrimSuffix(entry.Name(), ".json")
				
				// Try to load token to get expiry
				tokenFile := filepath.Join(tokenDir, entry.Name())
				data, err := os.ReadFile(tokenFile)
				if err != nil {
					fmt.Printf("Account: %s (Error reading token: %v)\n", accountID, err)
					continue
				}
				
				var token goauth2.Token
				if err := json.Unmarshal(data, &token); err != nil {
					fmt.Printf("Account: %s (Error parsing token: %v)\n", accountID, err)
					continue
				}
				
				// Print token info
				fmt.Printf("Account: %s\n", accountID)
				fmt.Printf("  Expires: %s\n", token.Expiry.Format("2006-01-02 15:04:05"))
				fmt.Printf("  Valid: %v\n", token.Valid())
				fmt.Println()
			}
		}
	}
	
	if !foundTokens {
		fmt.Println("No OAuth2 tokens found")
	}
}

func deleteOAuth2Token(cmd *cobra.Command, args []string) {
	configID := args[0]
	
	// Load configuration
	cfg, err := config.GetConfig(configID)
	if err != nil {
		fmt.Printf("Error: Failed to load configuration: %v\n", err)
		os.Exit(1)
	}
	
	// Check if OAuth2 is enabled
	if !cfg.Email.Protocols.IMAP.Security.OAuth2.Enabled {
		fmt.Printf("Error: OAuth2 is not enabled for configuration %s\n", configID)
		os.Exit(1)
	}
	
	// Create token storage directory
	tokenDir := cfg.Email.Protocols.IMAP.Security.OAuth2.TokenStoragePath
	
	// Create account ID for token storage
	accountID := fmt.Sprintf("%s_%s", cfg.Meta.ID, cfg.Email.Protocols.IMAP.Username)
	
	// Create token file path
	tokenFile := filepath.Join(tokenDir, fmt.Sprintf("%s.json", accountID))
	
	// Check if token file exists
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		fmt.Printf("No OAuth2 token found for account %s\n", accountID)
		return
	}
	
	// Delete token file
	if err := os.Remove(tokenFile); err != nil {
		fmt.Printf("Error: Failed to delete token file: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("OAuth2 token deleted for account %s\n", accountID)
}

// For standalone testing
func main() {
	// Initialize the config store
	configDir := "/opt/email-extractor/config"
	if envConfigDir := os.Getenv("CONFIG_DIR"); envConfigDir != "" {
		configDir = envConfigDir
	}
	
	// Initialize the config store
	if err := initConfigStore(configDir); err != nil {
		fmt.Printf("Error: Failed to initialize config store: %v\n", err)
		fmt.Println("Using current directory as fallback...")
		
		// Try current directory as fallback
		currentDir, err := os.Getwd()
		if err != nil {
			fmt.Printf("Error: Failed to get current directory: %v\n", err)
			os.Exit(1)
		}
		
		// Try to find config directory in current directory or parent directories
		configPath := findConfigDir(currentDir)
		if configPath == "" {
			fmt.Println("Error: Could not find config directory")
			os.Exit(1)
		}
		
		fmt.Printf("Found config directory: %s\n", configPath)
		if err := initConfigStore(configPath); err != nil {
			fmt.Printf("Error: Failed to initialize config store with fallback path: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Create the root command
	rootCmd := &cobra.Command{
		Use:   "email-extractor",
		Short: "Email Extractor",
		Long:  `Email Extractor is a service that automatically downloads emails and extracts attachments`,
	}
	
	// Add the OAuth2 command to the root command
	rootCmd.AddCommand(CreateOAuth2Command())
	
	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// initConfigStore initializes the configuration store
func initConfigStore(configDir string) error {
	// Check if the directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return fmt.Errorf("config directory does not exist: %s", configDir)
	}

	// Load the default configuration
	configFile := filepath.Join(configDir, "default.config.yaml")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return fmt.Errorf("default configuration file does not exist: %s", configFile)
	}

	// Read the configuration file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Parse the configuration
	var cfg types.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse configuration file: %w", err)
	}

	// Store the configuration
	config.SetConfig("default", &cfg)

	return nil
}

// findConfigDir tries to find the config directory in the current directory or parent directories
func findConfigDir(startDir string) string {
	// Check if the config directory exists in the current directory
	configPath := filepath.Join(startDir, "config")
	if _, err := os.Stat(configPath); err == nil {
		// Check if default.config.yaml exists
		if _, err := os.Stat(filepath.Join(configPath, "default.config.yaml")); err == nil {
			return configPath
		}
	}
	
	// Check if we're at the root directory
	parentDir := filepath.Dir(startDir)
	if parentDir == startDir {
		return "" // We've reached the root directory
	}
	
	// Recursively check parent directories
	return findConfigDir(parentDir)
} 