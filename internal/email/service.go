package email

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/altafino/email-extractor/internal/models"
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
	// Add debug logging at the start
	s.logger.Debug("processing emails with config",
		"attachment_naming_pattern", s.cfg.Email.Attachments.NamingPattern)

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

		imapClient, err := NewIMAPClient(s.cfg, s.logger)
		if err != nil {
			return fmt.Errorf("failed to create IMAP client: %w", err)
		}
		defer imapClient.Close()

		if err := imapClient.Connect(context.Background()); err != nil {
			return fmt.Errorf("failed to connect to IMAP server: %w", err)
		}

		if err := imapClient.FetchMessages(context.Background()); err != nil {
			return fmt.Errorf("failed to fetch IMAP messages: %w", err)
		}
	}

	// Process POP3 if enabled
	if s.cfg.Email.Protocols.POP3.Enabled {
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

		// Create email config from settings
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
			return fmt.Errorf("failed to download emails: %w", err)
		}

		// Log results
		for _, result := range results {
			if result.Status == "error" {
				s.logger.Error("failed to process email",
					"message_id", result.MessageID,
					"error", result.ErrorMessage,
				)
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

func (s *Service) addDomainIfNeeded(username, server string) string {
	if strings.Contains(username, "@") {
		return username
	}
	// Extract domain from server (remove any pop3/pop/imap prefix)
	domain := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(server, "pop3."), "pop."), "imap.")
	return username + "@" + domain
}
