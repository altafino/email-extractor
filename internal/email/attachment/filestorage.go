package attachment

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileStorage implementation of Save to store attachments on disk
func (fs *FileStorage) Save(filename string, content []byte, config AttachmentConfig) (string, error) {
	// Validate content size
	if int64(len(content)) > config.MaxSize {
		return "", fmt.Errorf("attachment size %d exceeds maximum allowed size %d", len(content), config.MaxSize)
	}

	// First sanitize if configured (before pattern application)
	if config.SanitizeFilenames {
		filename = SanitizeFilename(filename)
	}

	// Apply the naming pattern
	filename = GenerateFilename(filename, time.Now().UTC(), config.FilenamePattern)

	// Ensure filename has correct extension
	ext := strings.ToLower(filepath.Ext(filename))
	baseFilename := strings.TrimSuffix(filename, ext)

	// If the extension is uppercase, convert it to lowercase
	if ext != strings.ToLower(ext) {
		filename = baseFilename + strings.ToLower(ext)
	}

	// If no extension, try to detect from content
	if ext == "" {
		contentType := http.DetectContentType(content)
		if mimeExt, ok := MimeToExt[contentType]; ok {
			filename = filename + mimeExt
			ext = mimeExt
		}
	}

	// Sanitize filename if configured
	if config.SanitizeFilenames {
		filename = SanitizeFilename(filename)
	}

	// Process storage path with date variables
	now := time.Now().UTC()
	storagePath := config.StoragePath

	// Check if the storage path contains variables
	hasVars := strings.Contains(storagePath, "${")

	fs.logger.Debug("processing storage path",
		"original", storagePath,
		"has_vars", hasVars,
		"account", config.AccountName)

	// Replace variables in storage path
	if hasVars {
		storagePath = fs.processStoragePath(storagePath, now, config.AccountName)
	}

	// Determine the final directory path
	finalDir := fs.getFinalDirectory(storagePath, hasVars, config.PreserveStructure, now)

	fs.logger.Debug("final directory path",
		"final_dir", finalDir)

	// Create the directory
	if err := os.MkdirAll(finalDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Get final path and handle duplicates
	finalPath := fs.getUniquePath(filepath.Join(finalDir, filename))

	// Create and write file
	if err := fs.writeFile(finalPath, content); err != nil {
		return "", err
	}

	return finalPath, nil
}

// Helper methods for FileStorage
func (fs *FileStorage) processStoragePath(path string, now time.Time, accountName string) string {
	replacements := map[string]string{
		"${YYYY}":    now.Format("2006"),
		"${YY}":      now.Format("06"),
		"${MM}":      now.Format("01"),
		"${DD}":      now.Format("02"),
		"${HH}":      now.Format("15"),
		"${mm}":      now.Format("04"),
		"${ss}":      now.Format("05"),
		"${account}": accountName,
	}

	for pattern, replacement := range replacements {
		path = strings.ReplaceAll(path, pattern, replacement)
	}

	return path
}

func (fs *FileStorage) getFinalDirectory(storagePath string, hasVars, preserveStructure bool, now time.Time) string {
	if preserveStructure && !hasVars {
		dateDir := now.Format("2006/01/02")
		return filepath.Join(storagePath, dateDir)
	}
	return storagePath
}

func (fs *FileStorage) getUniquePath(path string) string {
	if _, err := os.Stat(path); err == nil {
		ext := filepath.Ext(path)
		base := strings.TrimSuffix(path, ext)
		path = fmt.Sprintf("%s_%d%s", base, time.Now().UnixNano(), ext)
	}
	return path
}

func (fs *FileStorage) writeFile(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		os.Remove(path) // Clean up on error
		return fmt.Errorf("failed to write file content: %w", err)
	}
	return nil
}
