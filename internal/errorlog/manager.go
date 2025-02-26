package errorlog

import (
	"fmt"
	"log/slog"

	"github.com/altafino/email-extractor/internal/types"
)

// Manager handles email error logging operations
type Manager struct {
	cfg    *types.Config
	logger *slog.Logger
	impl   Logger
}

// NewManager creates a new error logging manager
func NewManager(cfg *types.Config, logger *slog.Logger) (*Manager, error) {
	if !cfg.Email.ErrorLogging.Enabled {
		logger.Debug("email error logging is disabled")
		return &Manager{
			cfg:    cfg,
			logger: logger,
			impl:   &noopLogger{},
		}, nil
	}

	var impl Logger
	var err error

	switch cfg.Email.ErrorLogging.StorageType {
	case "file", "":
		impl, err = NewFileLogger(cfg, logger)
	// Add other storage types here as needed
	// case "database":
	//     impl, err = NewDatabaseLogger(cfg, logger)
	default:
		return nil, fmt.Errorf("unsupported error logging storage type: %s", cfg.Email.ErrorLogging.StorageType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize error logger: %w", err)
	}

	return &Manager{
		cfg:    cfg,
		logger: logger,
		impl:   impl,
	}, nil
}

// LogError records an email processing error
func (m *Manager) LogError(err EmailError) error {
	// Set config ID if not provided
	if err.ConfigID == "" {
		err.ConfigID = m.cfg.Meta.ID
	}
	
	m.logger.Debug("attempting to log email error",
		"error_type", err.ErrorType,
		"message_id", err.MessageID,
		"sender", err.Sender,
		"subject", err.Subject,
		"config_id", err.ConfigID,
		"storage_path", m.cfg.Email.ErrorLogging.StoragePath,
		"enabled", m.cfg.Email.ErrorLogging.Enabled)
	
	return m.impl.LogError(err)
}

// GetErrors retrieves errors based on filters
func (m *Manager) GetErrors(filters map[string]string) ([]EmailError, error) {
	return m.impl.GetErrors(filters)
}

// CleanupOldErrors removes errors older than the retention period
func (m *Manager) CleanupOldErrors() error {
	return m.impl.CleanupOldErrors()
}

// Close releases any resources used by the logger
func (m *Manager) Close() error {
	return m.impl.Close()
}

// noopLogger is a no-operation implementation of Logger for when logging is disabled
type noopLogger struct{}

func (n *noopLogger) LogError(err EmailError) error                       { return nil }
func (n *noopLogger) GetErrors(filters map[string]string) ([]EmailError, error) { return nil, nil }
func (n *noopLogger) CleanupOldErrors() error                             { return nil }
func (n *noopLogger) Close() error                                        { return nil } 