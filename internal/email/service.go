package email

import (
	"fmt"
	"log/slog"

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
	s.logger.Info("starting email processing",
		"config_id", s.cfg.Meta.ID,
	)

	// Create email config from settings
	emailCfg := models.EmailConfig{
		Protocol:            "pop3",
		Server:              s.cfg.Email.Protocols.POP3.Server,
		Port:                s.cfg.Email.Protocols.POP3.DefaultPort,
		Username:            s.cfg.Email.Protocols.POP3.Username,
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
