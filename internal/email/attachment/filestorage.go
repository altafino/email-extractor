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

	// Store original extension and base name
	ext := strings.ToLower(filepath.Ext(filename))
	baseFilename := strings.TrimSuffix(filename, ext)

	// If no extension, try to detect from content
	if ext == "" {
		contentType := http.DetectContentType(content)
		if mimeExt, ok := MimeToExt[contentType]; ok {
			ext = mimeExt
		}
	}

	// First sanitize the base filename if configured
	if config.SanitizeFilenames {
		baseFilename = SanitizeFilename(baseFilename)
	}

	// Apply the naming pattern
	finalFilename := ""
	if config.FilenamePattern != "" {
		// Log the pattern and base filename
		fs.logger.Debug("applying filename pattern",
			"pattern", config.FilenamePattern,
			"base_filename", baseFilename)

		// Apply pattern to the base filename (without extension)
		patternedFilename := GenerateFilename(baseFilename, time.Now().UTC(), config.FilenamePattern)

		// Log the result after pattern application
		fs.logger.Debug("pattern applied",
			"patterned_filename", patternedFilename)

		// Sanitize the patterned filename if needed
		if config.SanitizeFilenames {
			patternedFilename = SanitizeFilename(patternedFilename)
			fs.logger.Debug("sanitized patterned filename",
				"sanitized_filename", patternedFilename)
		}

		// Make sure the extension is preserved
		finalFilename = patternedFilename
		if !strings.HasSuffix(finalFilename, ext) {
			finalFilename += ext
		}
	} else {
		finalFilename = baseFilename + ext
	}

	// Process storage path with date variables
	now := time.Now().UTC()
	storagePath := config.StoragePath

	// Check if the storage path contains variables
	hasVars := strings.Contains(storagePath, "${")

	// Replace variables in storage path
	if hasVars {
		storagePath = fs.processStoragePath(storagePath, now, config.AccountName)
	}

	// Determine the final directory path
	finalDir := fs.getFinalDirectory(storagePath, hasVars, config.PreserveStructure, now)

	// Create the directory
	if err := os.MkdirAll(finalDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Get final path and handle duplicates
	finalPath := fs.getUniquePath(filepath.Join(finalDir, finalFilename))

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
