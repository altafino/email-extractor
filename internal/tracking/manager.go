package tracking

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/altafino/email-extractor/internal/types"
)

// Manager handles email tracking operations
type Manager struct {
	cfg     *types.Config
	logger  *slog.Logger
	storage Storage
	mu      sync.Mutex
}

// NewManager creates a new tracking manager
func NewManager(cfg *types.Config, logger *slog.Logger) (*Manager, error) {
	if !cfg.Email.Tracking.Enabled {
		logger.Debug("email tracking is disabled")
		return &Manager{
			cfg:    cfg,
			logger: logger,
		}, nil
	}

	storage, err := NewStorage(cfg.Email.Tracking.StorageType, cfg.Email.Tracking.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tracking storage: %w", err)
	}

	if err := storage.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize tracking storage: %w", err)
	}

	logger.Debug("initialized email tracking",
		"storage_type", cfg.Email.Tracking.StorageType,
		"storage_path", cfg.Email.Tracking.StoragePath)

	return &Manager{
		cfg:     cfg,
		logger:  logger,
		storage: storage,
	}, nil
}

// Close cleans up resources
func (m *Manager) Close() error {
	if m.storage != nil {
		return m.storage.Close()
	}
	return nil
}

// TrackEmail records a downloaded email
func (m *Manager) TrackEmail(protocol, server, username, messageID, subject, status string) error {
	if !m.cfg.Email.Tracking.Enabled || m.storage == nil {
		return nil // Tracking is disabled, silently succeed
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	record := EmailRecord{
		MessageID:    messageID,
		Protocol:     protocol,
		Server:       server,
		Username:     username,
		Subject:      subject,
		DownloadedAt: time.Now().UTC(),
		Status:       status,
	}

	if err := m.storage.AddRecord(record); err != nil {
		m.logger.Error("failed to track email",
			"message_id", messageID,
			"error", err)
		return err
	}

	m.logger.Debug("tracked email",
		"message_id", messageID,
		"protocol", protocol,
		"server", server,
		"username", username)

	return nil
}

// IsEmailDownloaded checks if an email has already been downloaded
func (m *Manager) IsEmailDownloaded(protocol, server, username, messageID string) (bool, error) {
	if !m.cfg.Email.Tracking.Enabled || !m.cfg.Email.Tracking.TrackDownloaded || m.storage == nil {
		return false, nil // Tracking is disabled or not checking for downloaded emails
	}

	downloaded, err := m.storage.HasRecord(protocol, server, username, messageID)
	if err != nil {
		m.logger.Error("failed to check if email was downloaded",
			"message_id", messageID,
			"error", err)
		return false, err
	}

	if downloaded {
		m.logger.Debug("email already downloaded",
			"message_id", messageID,
			"protocol", protocol,
			"server", server,
			"username", username)
	}

	return downloaded, nil
}

// CleanupOldRecords removes records older than the retention period
func (m *Manager) CleanupOldRecords() error {
	if !m.cfg.Email.Tracking.Enabled || m.storage == nil {
		return nil // Tracking is disabled, silently succeed
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.storage.CleanupOldRecords(m.cfg.Email.Tracking.RetentionDays); err != nil {
		m.logger.Error("failed to clean up old records", "error", err)
		return err
	}

	m.logger.Info("cleaned up old email tracking records",
		"retention_days", m.cfg.Email.Tracking.RetentionDays)

	return nil
}

// MarkEmailDownloaded records a downloaded email with attachment information
func (m *Manager) MarkEmailDownloaded(protocol, server, username, messageID, sender, subject string, sentAt time.Time, attachmentCount int) error {
	if !m.cfg.Email.Tracking.Enabled || !m.cfg.Email.Tracking.TrackDownloaded || m.storage == nil {
		return nil // Tracking is disabled, silently succeed
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	record := EmailRecord{
		MessageID:    messageID,
		Protocol:     protocol,
		Server:       server,
		Username:     username,
		Subject:      subject,
		DownloadedAt: time.Now().UTC(),
		Status:       "downloaded",
	}

	if err := m.storage.AddRecord(record); err != nil {
		m.logger.Error("failed to mark email as downloaded",
			"message_id", messageID,
			"error", err)
		return err
	}

	m.logger.Debug("marked email as downloaded",
		"message_id", messageID,
		"protocol", protocol,
		"server", server,
		"username", username,
		"attachments", attachmentCount)

	return nil
}
