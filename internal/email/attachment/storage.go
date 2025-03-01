package attachment

import (
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
