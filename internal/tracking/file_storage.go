package tracking

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileStorage implements the Storage interface using the filesystem
type FileStorage struct {
	basePath    string
	recordsPath string
	mu          sync.RWMutex
	initialized bool
}

// NewFileStorage creates a new file-based storage
func NewFileStorage(basePath string) (*FileStorage, error) {
	if basePath == "" {
		return nil, fmt.Errorf("base path cannot be empty")
	}

	return &FileStorage{
		basePath:    basePath,
		recordsPath: filepath.Join(basePath, "email_records.json"),
	}, nil
}

// Initialize prepares the storage for use
func (fs *FileStorage) Initialize() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Create the base directory if it doesn't exist
	if err := os.MkdirAll(fs.basePath, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Create the records file if it doesn't exist
	if _, err := os.Stat(fs.recordsPath); os.IsNotExist(err) {
		// Create an empty records file
		if err := fs.saveRecords([]EmailRecord{}); err != nil {
			return fmt.Errorf("failed to create records file: %w", err)
		}
	}

	fs.initialized = true
	return nil
}

// Close cleans up any resources
func (fs *FileStorage) Close() error {
	// No resources to clean up for file storage
	return nil
}

// AddRecord adds a new email record
func (fs *FileStorage) AddRecord(record EmailRecord) error {
	if !fs.initialized {
		return ErrStorageNotInitialized
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Load existing records
	records, err := fs.loadRecordsLocked()
	if err != nil {
		return err
	}

	// Add the new record
	records = append(records, record)

	// Save the updated records
	return fs.saveRecords(records)
}

// HasRecord checks if an email has already been downloaded
func (fs *FileStorage) HasRecord(protocol, server, username, messageID string) (bool, error) {
	if !fs.initialized {
		return false, ErrStorageNotInitialized
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	records, err := fs.loadRecordsLocked()
	if err != nil {
		return false, err
	}

	for _, record := range records {
		if record.Protocol == protocol &&
			record.Server == server &&
			record.Username == username &&
			record.MessageID == messageID {
			return true, nil
		}
	}

	return false, nil
}

// GetRecords retrieves all email records, optionally filtered
func (fs *FileStorage) GetRecords(filter map[string]string) ([]EmailRecord, error) {
	if !fs.initialized {
		return nil, ErrStorageNotInitialized
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	records, err := fs.loadRecordsLocked()
	if err != nil {
		return nil, err
	}

	// If no filter is provided, return all records
	if filter == nil || len(filter) == 0 {
		return records, nil
	}

	// Apply filters
	var filteredRecords []EmailRecord
	for _, record := range records {
		match := true
		for key, value := range filter {
			switch key {
			case "protocol":
				if record.Protocol != value {
					match = false
				}
			case "server":
				if record.Server != value {
					match = false
				}
			case "username":
				if record.Username != value {
					match = false
				}
			case "message_id":
				if record.MessageID != value {
					match = false
				}
			case "status":
				if record.Status != value {
					match = false
				}
			}
			if !match {
				break
			}
		}
		if match {
			filteredRecords = append(filteredRecords, record)
		}
	}

	return filteredRecords, nil
}

// CleanupOldRecords removes records older than the specified retention period
func (fs *FileStorage) CleanupOldRecords(retentionDays int) error {
	if !fs.initialized {
		return ErrStorageNotInitialized
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	records, err := fs.loadRecordsLocked()
	if err != nil {
		return err
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	var newRecords []EmailRecord

	for _, record := range records {
		if record.DownloadedAt.After(cutoffTime) {
			newRecords = append(newRecords, record)
		}
	}

	return fs.saveRecords(newRecords)
}

// loadRecordsLocked loads all records from the file (assumes lock is held)
func (fs *FileStorage) loadRecordsLocked() ([]EmailRecord, error) {
	data, err := os.ReadFile(fs.recordsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read records file: %w", err)
	}

	// Handle empty file case
	if len(data) == 0 {
		return []EmailRecord{}, nil
	}

	var records []EmailRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("failed to parse records file: %w", err)
	}

	return records, nil
}

// saveRecords saves all records to the file
func (fs *FileStorage) saveRecords(records []EmailRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize records: %w", err)
	}

	if err := os.WriteFile(fs.recordsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write records file: %w", err)
	}

	return nil
} 