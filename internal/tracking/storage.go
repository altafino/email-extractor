package tracking

import (
	"errors"
	"time"
)

// EmailRecord represents a record of a downloaded email
type EmailRecord struct {
	MessageID    string    `json:"message_id"`
	Protocol     string    `json:"protocol"`
	Server       string    `json:"server"`
	Username     string    `json:"username"`
	Subject      string    `json:"subject,omitempty"`
	DownloadedAt time.Time `json:"downloaded_at"`
	Status       string    `json:"status"`
}

// Storage defines the interface for tracking downloaded emails
type Storage interface {
	// Initialize prepares the storage for use
	Initialize() error

	// Close cleans up any resources used by the storage
	Close() error

	// AddRecord adds a new email record to the storage
	AddRecord(record EmailRecord) error

	// HasRecord checks if an email with the given ID has already been downloaded
	HasRecord(protocol, server, username, messageID string) (bool, error)

	// GetRecords retrieves all email records, optionally filtered
	GetRecords(filter map[string]string) ([]EmailRecord, error)

	// CleanupOldRecords removes records older than the specified retention period
	CleanupOldRecords(retentionDays int) error
}

// NewStorage creates a new storage implementation based on the specified type
func NewStorage(storageType, storagePath string) (Storage, error) {
	switch storageType {
	case "file":
		return NewFileStorage(storagePath)
	case "database":
		// Future implementation
		return nil, ErrUnsupportedStorageType
	default:
		return nil, ErrUnsupportedStorageType
	}
}

// Common errors
var (
	ErrUnsupportedStorageType = errors.New("unsupported storage type")
	ErrStorageNotInitialized  = errors.New("storage not initialized")
	ErrRecordNotFound         = errors.New("record not found")
) 