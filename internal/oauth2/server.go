package oauth2

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// StartLocalServer starts a local HTTP server to handle OAuth2 callback
func StartLocalServer(ctx context.Context, logger *slog.Logger) (string, error) {
	// Create a channel to receive the authorization code
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	
	// Create a server with a random available port
	listener, err := net.Listen("tcp", "localhost:8085")
	if err != nil {
		return "", fmt.Errorf("failed to start local server: %w", err)
	}
	
	server := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
	}
	
	// Set up the handler for the OAuth2 callback
	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		// Get the authorization code from the query parameters
		code := r.URL.Query().Get("code")
		if code == "" {
			errChan <- fmt.Errorf("no code in callback")
			http.Error(w, "No code provided", http.StatusBadRequest)
			return
		}
		
		// Send the code to the channel
		codeChan <- code
		
		// Return a success page to the user
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `
			<html>
				<head>
					<title>Authentication Successful</title>
					<style>
						body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
						.success { color: green; font-size: 24px; margin-bottom: 20px; }
						.info { margin-bottom: 20px; }
					</style>
				</head>
				<body>
					<div class="success">Authentication Successful!</div>
					<div class="info">You can now close this window and return to the application.</div>
				</body>
			</html>
		`)
	})
	
	// Start the server in a goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("server error: %w", err)
		}
	}()
	
	// Get the server URL
	serverURL := fmt.Sprintf("http://%s", listener.Addr().String())
	logger.Debug("started local OAuth2 server", "url", serverURL)
	
	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	
	// Wait for the code or an error
	select {
	case code := <-codeChan:
		// Shutdown the server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		return code, nil
	case err := <-errChan:
		// Shutdown the server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		return "", err
	case <-timeoutCtx.Done():
		// Shutdown the server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		return "", fmt.Errorf("timeout waiting for authorization")
	}
} 