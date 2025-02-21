package email

import (
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
	return &Service{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *Service) ProcessEmails() error {
	// Check if POP3 is enabled
	if !s.cfg.Email.Protocols.POP3.Enabled {
		s.logger.Info("POP3 protocol is disabled, skipping email processing",
			"config_id", s.cfg.Meta.ID,
		)
		return nil
	}

	// Log the actual values being used
	s.logger.Debug("POP3 configuration",
		"server", s.cfg.Email.Protocols.POP3.Server,
		"port", s.cfg.Email.Protocols.POP3.DefaultPort,
		"username", s.cfg.Email.Protocols.POP3.Username,
		"tls_enabled", s.cfg.Email.Security.TLS.Enabled,
		"delete_after_download", s.cfg.Email.Protocols.POP3.DeleteAfterDownload,
	)

	// Validate required POP3 settings
	if s.cfg.Email.Protocols.POP3.Server == "" ||
		s.cfg.Email.Protocols.POP3.Username == "" ||
		s.cfg.Email.Protocols.POP3.Password == "" {
		return fmt.Errorf("incomplete POP3 configuration: server, username and password are required")
	}

	s.logger.Info("starting email processing",
		"config_id", s.cfg.Meta.ID,
		"server", s.cfg.Email.Protocols.POP3.Server,
		"username", s.cfg.Email.Protocols.POP3.Username,
	)

	// Create email config from settings
	emailCfg := models.EmailConfig{
		Protocol:            "pop3",
		Server:              s.cfg.Email.Protocols.POP3.Server,
		Port:                s.cfg.Email.Protocols.POP3.DefaultPort,
		Username:            s.addDomainIfNeeded(s.cfg.Email.Protocols.POP3.Username, s.cfg.Email.Protocols.POP3.Server),
		Password:            s.cfg.Email.Protocols.POP3.Password,
		EnableTLS:           s.cfg.Email.Security.TLS.Enabled,
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
