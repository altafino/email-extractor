package app

import (
	"context"
	"log/slog"

	"github.com/altafino/email-extractor/internal/email"
	"github.com/altafino/email-extractor/internal/types"
)

// Scheduler handles periodic email processing
type Scheduler struct {
	configs []*types.Config
	logger  *slog.Logger
	service *email.Service
}

// NewScheduler creates a new scheduler instance
func NewScheduler(configs []*types.Config, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		configs: configs,
		logger:  logger,
	}
}

// Start begins the scheduling of email processing
func (s *Scheduler) Start(ctx context.Context) error {
	for _, cfg := range s.configs {
		if !cfg.Meta.Enabled {
			s.logger.Info("skipping disabled config", "config_id", cfg.Meta.ID)
			continue
		}

		// Skip if no protocols are enabled
		if !cfg.Email.Protocols.POP3.Enabled && !cfg.Email.Protocols.IMAP.Enabled {
			s.logger.Info("skipping config with no enabled protocols",
				"config_id", cfg.Meta.ID,
			)
			continue
		}

		service := email.NewService(cfg, s.logger)
		if err := service.ProcessEmails(); err != nil {
			s.logger.Error("failed to process emails",
				"config_id", cfg.Meta.ID,
				"error", err,
			)
		}
	}

	return nil
}
