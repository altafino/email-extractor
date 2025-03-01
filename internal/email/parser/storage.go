package parser

import (
	"log/slog"
)

// Storage interface defines methods for saving attachments.
type Storage interface {
	Save(filename string, content []byte, config AttachmentConfig, logger *slog.Logger) (string, error)
	// You could add other methods here, like Delete, List, etc., if needed.
}

// FileStorage implements the Storage interface using local file system.
type FileStorage struct {
	StoragePath string
}

// Save saves the attachment to the local file system (empty implementation for now).
func (fs *FileStorage) Save(filename string, content []byte, config AttachmentConfig, logger *slog.Logger) (string, error) {
	// TODO: Implement file saving logic here later.
	// This is just a placeholder to satisfy the interface.
	return "", nil
} 