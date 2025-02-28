package email

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/errorlog"
	"github.com/altafino/email-extractor/internal/models"
	"github.com/altafino/email-extractor/internal/tracking"
	"github.com/altafino/email-extractor/internal/types"
)

type Service struct {
	cfg    *types.Config
	logger *slog.Logger
}

func NewService(cfg *types.Config, logger *slog.Logger) *Service {
	// Add debug logging for config
	logger.Debug("creating email service",
		"config_id", cfg.Meta.ID,
		"attachment_config", cfg.Email.Attachments)

	return &Service{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *Service) ProcessEmails() error {
	// Add extensive debug logging for configuration
	s.logger.Debug("processing emails with full protocol configuration",
		"imap_enabled", s.cfg.Email.Protocols.IMAP.Enabled,
		"imap_server", s.cfg.Email.Protocols.IMAP.Server,
		"pop3_enabled", s.cfg.Email.Protocols.POP3.Enabled,
		"pop3_server", s.cfg.Email.Protocols.POP3.Server,
		"config_id", s.cfg.Meta.ID)

	// Add debug logging for protocol configuration
	s.logger.Debug("email protocol configuration",
		"imap_enabled", s.cfg.Email.Protocols.IMAP.Enabled,
		"pop3_enabled", s.cfg.Email.Protocols.POP3.Enabled)

	// Add debug logging at the start
	s.logger.Debug("processing emails with config",
		"attachment_naming_pattern", s.cfg.Email.Attachments.NamingPattern,
		"track_downloaded", s.cfg.Email.Tracking.TrackDownloaded)

	// Initialize tracking manager for cleanup
	if s.cfg.Email.Tracking.Enabled {
		trackingManager, err := tracking.NewManager(s.cfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to initialize tracking manager for cleanup", "error", err)
			// Continue without tracking cleanup
		} else {
			defer trackingManager.Close()

			// Clean up old records
			if err := trackingManager.CleanupOldRecords(); err != nil {
				s.logger.Warn("failed to clean up old tracking records", "error", err)
				// Continue processing
			}
		}
	}

	// Create error logging manager for the entire process
	var errorLogger *errorlog.Manager
	if s.cfg.Email.ErrorLogging.Enabled {
		// Ensure directory exists
		if err := os.MkdirAll(s.cfg.Email.ErrorLogging.StoragePath, 0755); err != nil {
			s.logger.Warn("failed to create error log directory",
				"path", s.cfg.Email.ErrorLogging.StoragePath,
				"error", err)
		} else {
			// Check if directory is writable
			testFile := filepath.Join(s.cfg.Email.ErrorLogging.StoragePath, ".test_write")
			if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
				s.logger.Error("error log directory is not writable",
					"path", s.cfg.Email.ErrorLogging.StoragePath,
					"error", err)
			} else {
				os.Remove(testFile) // Clean up test file
				s.logger.Debug("error log directory is writable",
					"path", s.cfg.Email.ErrorLogging.StoragePath)
			}
		}

		var err error
		errorLogger, err = errorlog.NewManager(s.cfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to initialize error logger for cleanup",
				"error", err,
				"config", s.cfg.Email.ErrorLogging)
			// Continue without error log cleanup
		} else {
			defer errorLogger.Close()

			// Clean up old error logs
			if err := errorLogger.CleanupOldErrors(); err != nil {
				s.logger.Warn("failed to clean up old error logs", "error", err)
				// Continue processing
			}
		}
	}

	// Check which protocol is enabled
	if !s.cfg.Email.Protocols.POP3.Enabled && !s.cfg.Email.Protocols.IMAP.Enabled {
		s.logger.Info("No email protocols enabled, skipping email processing",
			"config_id", s.cfg.Meta.ID,
		)
		return nil
	}

	// Process IMAP if enabled
	if s.cfg.Email.Protocols.IMAP.Enabled {
		s.logger.Info("Starting IMAP processing",
			"config_id", s.cfg.Meta.ID,
			"server", s.cfg.Email.Protocols.IMAP.Server,
			"username", s.cfg.Email.Protocols.IMAP.Username,
		)

		// Validate required IMAP settings
		if s.cfg.Email.Protocols.IMAP.Server == "" ||
			s.cfg.Email.Protocols.IMAP.Username == "" ||
			s.cfg.Email.Protocols.IMAP.Password == "" {
			return fmt.Errorf("incomplete IMAP configuration: server, username and password are required")
		}

		// Create email config from settings
		emailCfg := models.EmailConfig{
			Protocol:  "imap",
			Server:    s.cfg.Email.Protocols.IMAP.Server,
			Port:      s.cfg.Email.Protocols.IMAP.DefaultPort,
			Username:  s.addDomainIfNeeded(s.cfg.Email.Protocols.IMAP.Username, s.cfg.Email.Protocols.IMAP.Server),
			Password:  s.cfg.Email.Protocols.IMAP.Password,
			EnableTLS: s.cfg.Email.Protocols.IMAP.Security.TLS.Enabled,
			DeleteAfterDownload: s.cfg.Email.Protocols.IMAP.DeleteAfterDownload,
			Folders:             s.cfg.Email.Protocols.IMAP.Folders,
		}
		s.logger.Info("emailCfg", "emailCfg", emailCfg)

		client, err := NewIMAPClient(s.cfg, s.logger)
		if err != nil {
			return fmt.Errorf("failed to create IMAP client: %w", err)
		}
		defer client.Close()

		// Connect to the IMAP server before fetching messages
		if err := client.Connect(context.Background()); err != nil {
			return fmt.Errorf("failed to connect to IMAP server: %w", err)
		}

		// Now fetch messages after connection is established
		if err := client.FetchMessages(context.Background()); err != nil {
			s.logger.Error("failed to fetch messages", "error", err)
			return fmt.Errorf("failed to fetch messages: %w", err)
		}
		s.logger.Info("successfully fetched messages")

		// The results variable is no longer needed since FetchMessages returns an error
		// results := client.FetchMessages(context.Background())
	} else {
		s.logger.Info("IMAP processing disabled, skipping")
	}

	// Process POP3 if enabled - explicitly check the Enabled flag
	if s.cfg.Email.Protocols.POP3.Enabled == false {
		s.logger.Info("POP3 processing disabled, skipping")
	} else {
		s.logger.Info("Starting POP3 processing",
			"config_id", s.cfg.Meta.ID,
			"server", s.cfg.Email.Protocols.POP3.Server,
			"username", s.cfg.Email.Protocols.POP3.Username,
		)

		// Validate required POP3 settings
		if s.cfg.Email.Protocols.POP3.Server == "" ||
			s.cfg.Email.Protocols.POP3.Username == "" ||
			s.cfg.Email.Protocols.POP3.Password == "" {
			return fmt.Errorf("incomplete POP3 configuration: server, username and password are required")
		}

		// Create email config from settings for pop3
		emailCfg := models.EmailConfig{
			Protocol:            "pop3",
			Server:              s.cfg.Email.Protocols.POP3.Server,
			Port:                s.cfg.Email.Protocols.POP3.DefaultPort,
			Username:            s.addDomainIfNeeded(s.cfg.Email.Protocols.POP3.Username, s.cfg.Email.Protocols.POP3.Server),
			Password:            s.cfg.Email.Protocols.POP3.Password,
			EnableTLS:           s.cfg.Email.Protocols.POP3.Security.TLS.Enabled,
			DeleteAfterDownload: s.cfg.Email.Protocols.POP3.DeleteAfterDownload,
		}

		client := NewPOP3Client(s.cfg, s.logger)
		results, err := client.DownloadEmails(models.EmailDownloadRequest{
			Config: emailCfg,
			Async:  false,
		})

		if err != nil {
			errMsg := fmt.Sprintf("failed to download emails: %v", err)
			s.logger.Error(errMsg)

			// Log the error
			if errorLogger != nil {
				errorLogger.LogError(errorlog.EmailError{
					Protocol:  "pop3",
					Server:    emailCfg.Server,
					Username:  emailCfg.Username,
					ErrorTime: time.Now().UTC(),
					ErrorType: "download_emails",
					ErrorMsg:  errMsg,
				})
			}

			return fmt.Errorf(errMsg)
		}

		// Log results
		for _, result := range results {
			if result.Status == "error" {
				s.logger.Error("failed to process email",
					"message_id", result.MessageID,
					"error", result.ErrorMessage,
				)

				// Log the error
				if errorLogger != nil {
					errorLogger.LogError(errorlog.EmailError{
						Protocol:  "pop3",
						Server:    emailCfg.Server,
						Username:  emailCfg.Username,
						MessageID: result.MessageID,
						Subject:   result.Subject,
						ErrorTime: time.Now().UTC(),
						ErrorType: "process_email",
						ErrorMsg:  result.ErrorMessage,
					})
				}

				continue
			}

			s.logger.Info("processed email",
				"message_id", result.MessageID,
				"subject", result.Subject,
				"attachments", len(result.Attachments),
				"status", result.Status,
			)
		}
	}

	return nil
}

func (s *Service) addDomainIfNeeded(username string, server string) string {
	if strings.Contains(username, "@") {
		return username
	}
	// Extract domain from server (remove any pop3/pop/imap prefix)
	domain := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(server, "pop3."), "pop."), "imap.")
	return username + "@" + domain
}
