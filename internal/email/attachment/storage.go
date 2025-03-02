package attachment

import (
	"context"
	"fmt"
	"log/slog"
)

// AttachmentStorage defines the interface for storing attachments
type AttachmentStorage interface {
	// Save stores the attachment content and returns the final path/identifier or error
	Save(filename string, content []byte, config AttachmentConfig) (string, error)
}

// NewFileStorage creates a new FileStorage instance
func NewFileStorage(logger *slog.Logger) AttachmentStorage {
	return &FileStorage{logger: logger}
}

// FileStorage implements AttachmentStorage for local filesystem
type FileStorage struct {
	logger *slog.Logger
}

// StorageType represents the type of storage backend
type StorageType string

const (
	StorageTypeFile   StorageType = "file"
	StorageTypeGDrive StorageType = "gdrive"
)

// StorageConfig holds configuration for creating storage instances
type StorageConfig struct {
	Type            StorageType
	CredentialsFile string // Path to Google Drive credentials JSON file
	ParentFolderID  string // Google Drive folder ID where files will be stored
}

// NewStorage creates a new storage instance based on the configuration
func NewStorage(ctx context.Context, config StorageConfig, logger *slog.Logger) (AttachmentStorage, error) {
	switch config.Type {
	case StorageTypeFile:
		return NewFileStorage(logger), nil
	case StorageTypeGDrive:
		return NewGDriveStorage(ctx, logger, config.CredentialsFile, config.ParentFolderID)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.Type)
	}
}
