package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// TokenManager handles OAuth2 token acquisition and refresh
type TokenManager struct {
	config     *oauth2.Config
	token      *oauth2.Token
	logger     *slog.Logger
	mu         sync.RWMutex
	refreshing bool
	tokenFile  string
}

// NewTokenManager creates a new OAuth2 token manager
func NewTokenManager(config *oauth2.Config, tokenDir string, accountID string, logger *slog.Logger) (*TokenManager, error) {
	// Create token directory if it doesn't exist
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create token directory: %w", err)
	}

	tokenFile := filepath.Join(tokenDir, fmt.Sprintf("%s.json", accountID))

	tm := &TokenManager{
		config:    config,
		logger:    logger,
		tokenFile: tokenFile,
	}

	// Try to load existing token
	token, err := tm.loadToken()
	if err != nil {
		logger.Warn("failed to load OAuth2 token", "error", err)
		// Continue without token, will need to authenticate
	} else if token != nil {
		tm.token = token
		logger.Debug("loaded existing OAuth2 token", 
			"expires_at", token.Expiry.Format(time.RFC3339))
	}

	return tm, nil
}

// GetToken returns a valid OAuth2 token, refreshing if necessary
func (tm *TokenManager) GetToken(ctx context.Context) (*oauth2.Token, error) {
	tm.mu.RLock()
	token := tm.token
	tm.mu.RUnlock()

	// If we have a valid token, return it
	if token != nil && token.Valid() {
		return token, nil
	}

	// Otherwise, refresh the token
	return tm.RefreshToken(ctx)
}

// RefreshToken refreshes the OAuth2 token
func (tm *TokenManager) RefreshToken(ctx context.Context) (*oauth2.Token, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check if token is still invalid after acquiring the lock
	if tm.token != nil && tm.token.Valid() {
		return tm.token, nil
	}

	// Prevent concurrent refreshes
	if tm.refreshing {
		return nil, fmt.Errorf("token refresh already in progress")
	}

	tm.refreshing = true
	defer func() { tm.refreshing = false }()

	// If we have a token with a refresh token, use it
	if tm.token != nil && tm.token.RefreshToken != "" {
		tm.logger.Debug("refreshing OAuth2 token using refresh token")
		tokenSource := tm.config.TokenSource(ctx, tm.token)
		newToken, err := tokenSource.Token()
		if err != nil {
			tm.logger.Error("failed to refresh OAuth2 token", "error", err)
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}

		// Store the new token
		tm.token = newToken
		tm.logger.Debug("OAuth2 token refreshed successfully", 
			"expires_at", newToken.Expiry.Format(time.RFC3339))

		// Save the token to file
		if err := tm.saveToken(newToken); err != nil {
			tm.logger.Warn("failed to save refreshed OAuth2 token", "error", err)
			// Continue with the token even if we couldn't save it
		}

		return newToken, nil
	}

	return nil, fmt.Errorf("no refresh token available")
}

// SetToken sets the OAuth2 token and saves it to disk
func (tm *TokenManager) SetToken(token *oauth2.Token) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tm.token = token
	return tm.saveToken(token)
}

// GetAccessToken returns just the access token string
func (tm *TokenManager) GetAccessToken(ctx context.Context) (string, error) {
	token, err := tm.GetToken(ctx)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// StartRefreshWorker starts a background worker to refresh the token before it expires
func (tm *TokenManager) StartRefreshWorker(ctx context.Context) {
	go func() {
		for {
			tm.mu.RLock()
			token := tm.token
			tm.mu.RUnlock()

			if token == nil {
				// No token yet, check again soon
				select {
				case <-time.After(30 * time.Second):
					continue
				case <-ctx.Done():
					return
				}
			}

			// Calculate time until token expires with a buffer
			expiresIn := token.Expiry.Sub(time.Now()) - 5*time.Minute
			if expiresIn < 0 {
				expiresIn = 0
			}

			// Wait until it's time to refresh
			select {
			case <-time.After(expiresIn):
				_, err := tm.RefreshToken(ctx)
				if err != nil {
					tm.logger.Error("background token refresh failed", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// loadToken loads an OAuth2 token from a file
func (tm *TokenManager) loadToken() (*oauth2.Token, error) {
	// Check if token file exists
	if _, err := os.Stat(tm.tokenFile); os.IsNotExist(err) {
		return nil, nil // No token file exists yet
	}
	
	// Read the token file
	data, err := os.ReadFile(tm.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}
	
	// Unmarshal the token from JSON
	var token oauth2.Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	
	return &token, nil
}

// saveToken saves an OAuth2 token to a file
func (tm *TokenManager) saveToken(token *oauth2.Token) error {
	// Marshal the token to JSON
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}
	
	// Write the token to the file
	if err := os.WriteFile(tm.tokenFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	
	return nil
} 