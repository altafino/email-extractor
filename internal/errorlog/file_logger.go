package errorlog

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/altafino/email-extractor/internal/types"
	"github.com/google/uuid"
)

// FileLogger implements the Logger interface using the filesystem
type FileLogger struct {
	cfg         *types.Config
	logger      *slog.Logger
	storagePath string
	mu          sync.Mutex
}

// NewFileLogger creates a new file-based error logger
func NewFileLogger(cfg *types.Config, logger *slog.Logger) (*FileLogger, error) {
	storagePath := cfg.Email.ErrorLogging.StoragePath

	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create error log directory: %w", err)
	}

	return &FileLogger{
		cfg:         cfg,
		logger:      logger,
		storagePath: storagePath,
	}, nil
}

// LogError records an email processing error to a JSON file
func (f *FileLogger) LogError(err EmailError) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.logger.Debug("starting to log error to file",
		"storage_path", f.storagePath,
		"error_type", err.ErrorType,
		"message_id", err.MessageID)

	// Generate a unique ID if not provided
	if err.ID == "" {
		err.ID = uuid.New().String()
		f.logger.Debug("generated new error ID", "id", err.ID)
	}

	// Set error time if not provided
	if err.ErrorTime.IsZero() {
		err.ErrorTime = time.Now().UTC()
		f.logger.Debug("set error time", "time", err.ErrorTime)
	}

	// Create a filename based on date and config ID
	dateStr := time.Now().UTC().Format("2006-01-02")
	filename := fmt.Sprintf("errors_%s_%s.json", err.ConfigID, dateStr)
	filePath := filepath.Join(f.storagePath, filename)

	f.logger.Debug("preparing to write to file",
		"file_path", filePath,
		"config_id", err.ConfigID,
		"date", dateStr)

	// Read existing errors or create new file
	var errors []EmailError
	if _, fileErr := os.Stat(filePath); fileErr == nil {
		f.logger.Debug("file exists, reading existing errors", "file_path", filePath)
		data, readErr := os.ReadFile(filePath)
		if readErr != nil {
			f.logger.Error("failed to read error log file",
				"file", filePath,
				"error", readErr)
			return fmt.Errorf("failed to read error log file: %w", readErr)
		}

		if err := json.Unmarshal(data, &errors); err != nil {
			// If file exists but can't be parsed, log warning and treat as empty
			f.logger.Warn("error log file exists but couldn't be parsed, creating new file",
				"file", filePath,
				"error", err)
			errors = []EmailError{}
		} else {
			f.logger.Debug("successfully read existing errors",
				"file", filePath,
				"count", len(errors))
		}
	} else {
		f.logger.Debug("file does not exist, creating new file", "file_path", filePath)
		errors = []EmailError{}
	}

	// Add new error and write back to file
	errors = append(errors, err)

	data, jsonErr := json.MarshalIndent(errors, "", "  ")
	if jsonErr != nil {
		f.logger.Error("failed to marshal error log", "error", jsonErr)
		return fmt.Errorf("failed to marshal error log: %w", jsonErr)
	}

	f.logger.Debug("writing error log to file",
		"file_path", filePath,
		"bytes", len(data),
		"errors_count", len(errors))

	if writeErr := os.WriteFile(filePath, data, 0644); writeErr != nil {
		f.logger.Error("failed to write error log file",
			"file", filePath,
			"error", writeErr)
		return fmt.Errorf("failed to write error log file: %w", writeErr)
	}

	f.logger.Info("successfully logged email error",
		"error_id", err.ID,
		"message_id", err.MessageID,
		"sender", err.Sender,
		"error_type", err.ErrorType,
		"file", filePath)

	return nil
}

// GetErrors retrieves errors based on filters
func (f *FileLogger) GetErrors(filters map[string]string) ([]EmailError, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var allErrors []EmailError

	// List all error log files
	files, err := os.ReadDir(f.storagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read error log directory: %w", err)
	}

	// Read each file and collect errors
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(f.storagePath, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			f.logger.Warn("failed to read error log file",
				"file", filePath,
				"error", err)
			continue
		}

		var fileErrors []EmailError
		if err := json.Unmarshal(data, &fileErrors); err != nil {
			f.logger.Warn("failed to parse error log file",
				"file", filePath,
				"error", err)
			continue
		}

		allErrors = append(allErrors, fileErrors...)
	}

	// Apply filters
	if len(filters) == 0 {
		return allErrors, nil
	}

	var filteredErrors []EmailError
	for _, err := range allErrors {
		match := true

		for key, value := range filters {
			switch key {
			case "config_id":
				if err.ConfigID != value {
					match = false
				}
			case "protocol":
				if err.Protocol != value {
					match = false
				}
			case "server":
				if err.Server != value {
					match = false
				}
			case "username":
				if err.Username != value {
					match = false
				}
			case "message_id":
				if err.MessageID != value {
					match = false
				}
			case "sender":
				if err.Sender != value {
					match = false
				}
			case "error_type":
				if err.ErrorType != value {
					match = false
				}
			}

			if !match {
				break
			}
		}

		if match {
			filteredErrors = append(filteredErrors, err)
		}
	}

	return filteredErrors, nil
}

// CleanupOldErrors removes errors older than the retention period
func (f *FileLogger) CleanupOldErrors() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	retentionDays := f.cfg.Email.ErrorLogging.RetentionDays
	if retentionDays <= 0 {
		// Default to 30 days if not specified
		retentionDays = 30
	}

	cutoffTime := time.Now().UTC().AddDate(0, 0, -retentionDays)
	f.logger.Debug("cleaning up old error logs",
		"retention_days", retentionDays,
		"cutoff_date", cutoffTime.Format("2006-01-02"))

	// List all error log files
	files, err := os.ReadDir(f.storagePath)
	if err != nil {
		return fmt.Errorf("failed to read error log directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		// Parse date from filename (errors_configid_YYYY-MM-DD.json)
		parts := filepath.Base(file.Name())
		// Find the date part in the filename
		var fileDate time.Time
		var parseErr error

		// Try to extract date from filename
		if len(parts) > 10 {
			for i := 0; i <= len(parts)-10; i++ {
				if datePart := parts[i : i+10]; len(datePart) == 10 {
					if fileDate, parseErr = time.Parse("2006-01-02", datePart); parseErr == nil {
						break
					}
				}
			}
		}

		// If we couldn't extract date from filename, check file modification time
		if fileDate.IsZero() {
			fileInfo, statErr := file.Info()
			if statErr != nil {
				f.logger.Warn("failed to get file info",
					"file", file.Name(),
					"error", statErr)
				continue
			}
			fileDate = fileInfo.ModTime()
		}

		// Delete file if older than retention period
		if fileDate.Before(cutoffTime) {
			filePath := filepath.Join(f.storagePath, file.Name())
			if err := os.Remove(filePath); err != nil {
				f.logger.Warn("failed to delete old error log file",
					"file", filePath,
					"error", err)
				continue
			}
			f.logger.Debug("deleted old error log file",
				"file", filePath,
				"date", fileDate.Format("2006-01-02"))
		}
	}

	return nil
}

// Close implements the Logger interface
func (f *FileLogger) Close() error {
	// No resources to release for file-based logger
	return nil
}
