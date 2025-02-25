package tracking

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileStorage implements the Storage interface using the filesystem
type FileStorage struct {
	basePath    string
	mu          sync.RWMutex
	initialized bool
	fileCache   map[string]string // Maps server+username to file path
}

// NewFileStorage creates a new file-based storage
func NewFileStorage(basePath string) (*FileStorage, error) {
	if basePath == "" {
		return nil, fmt.Errorf("base path cannot be empty")
	}

	return &FileStorage{
		basePath:  basePath,
		fileCache: make(map[string]string),
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

	fs.initialized = true
	return nil
}

// Close cleans up any resources
func (fs *FileStorage) Close() error {
	// No resources to clean up for file storage
	return nil
}

// getRecordsFilePath returns the path to the records file for the given server and username
func (fs *FileStorage) getRecordsFilePath(server, username string) string {
	// Create a safe filename from server and username
	key := fmt.Sprintf("%s_%s", server, username)
	
	if path, ok := fs.fileCache[key]; ok {
		return path
	}
	
	// Sanitize server and username for use in filename
	safeServer := sanitizeForFilename(server)
	safeUsername := sanitizeForFilename(username)
	
	// Create filename in format: server_username.json
	filename := fmt.Sprintf("%s_%s.json", safeServer, safeUsername)
	path := filepath.Join(fs.basePath, filename)
	
	// Cache the path
	fs.fileCache[key] = path
	
	return path
}

// sanitizeForFilename replaces unsafe characters in a string for use in a filename
func sanitizeForFilename(s string) string {
	// Replace common unsafe characters
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
		"@", "_at_",
	)
	return replacer.Replace(s)
}

// AddRecord adds a new email record
func (fs *FileStorage) AddRecord(record EmailRecord) error {
	if !fs.initialized {
		return ErrStorageNotInitialized
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	recordsPath := fs.getRecordsFilePath(record.Server, record.Username)
	
	// Load existing records
	records, err := fs.loadRecordsFromFile(recordsPath)
	if err != nil {
		return err
	}

	// Add the new record
	records = append(records, record)

	// Save the updated records
	return fs.saveRecordsToFile(recordsPath, records)
}

// HasRecord checks if an email has already been downloaded
func (fs *FileStorage) HasRecord(protocol, server, username, messageID string) (bool, error) {
	if !fs.initialized {
		return false, ErrStorageNotInitialized
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	recordsPath := fs.getRecordsFilePath(server, username)
	
	records, err := fs.loadRecordsFromFile(recordsPath)
	if err != nil {
		return false, err
	}

	for _, record := range records {
		if record.Protocol == protocol &&
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

	// If server and username are provided in the filter, we can load just that file
	if server, hasServer := filter["server"]; hasServer {
		if username, hasUsername := filter["username"]; hasUsername {
			recordsPath := fs.getRecordsFilePath(server, username)
			records, err := fs.loadRecordsFromFile(recordsPath)
			if err != nil {
				return nil, err
			}
			
			return fs.filterRecords(records, filter), nil
		}
	}

	// Otherwise, we need to load all files
	var allRecords []EmailRecord
	
	// Read all JSON files in the directory
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tracking directory: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			recordsPath := filepath.Join(fs.basePath, entry.Name())
			records, err := fs.loadRecordsFromFile(recordsPath)
			if err != nil {
				continue // Skip files that can't be read
			}
			allRecords = append(allRecords, records...)
		}
	}
	
	return fs.filterRecords(allRecords, filter), nil
}

// filterRecords applies filters to a list of records
func (fs *FileStorage) filterRecords(records []EmailRecord, filter map[string]string) []EmailRecord {
	// If no filter is provided, return all records
	if filter == nil || len(filter) == 0 {
		return records
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

	return filteredRecords
}

// CleanupOldRecords removes records older than the specified retention period
func (fs *FileStorage) CleanupOldRecords(retentionDays int) error {
	if !fs.initialized {
		return ErrStorageNotInitialized
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	
	// Read all JSON files in the directory
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		return fmt.Errorf("failed to read tracking directory: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			recordsPath := filepath.Join(fs.basePath, entry.Name())
			
			records, err := fs.loadRecordsFromFile(recordsPath)
			if err != nil {
				continue // Skip files that can't be read
			}
			
			var newRecords []EmailRecord
			for _, record := range records {
				if record.DownloadedAt.After(cutoffTime) {
					newRecords = append(newRecords, record)
				}
			}
			
			// If all records were removed, delete the file
			if len(newRecords) == 0 {
				os.Remove(recordsPath)
				continue
			}
			
			// Otherwise, save the filtered records
			fs.saveRecordsToFile(recordsPath, newRecords)
		}
	}

	return nil
}

// loadRecordsFromFile loads records from a specific file
func (fs *FileStorage) loadRecordsFromFile(path string) ([]EmailRecord, error) {
	// If file doesn't exist, return empty records
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []EmailRecord{}, nil
	}
	
	data, err := os.ReadFile(path)
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

// saveRecordsToFile saves records to a specific file
func (fs *FileStorage) saveRecordsToFile(path string, records []EmailRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize records: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write records file: %w", err)
	}

	return nil
} 