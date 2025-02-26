package u_io

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CleanFilename removes potentially dangerous characters from filenames
func CleanFilename(filename string) string {
	// Replace any path separators
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")

	// Remove any other potentially dangerous characters
	filename = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' || r == ' ' {
			return r
		}
		return '_'
	}, filename)

	// Trim spaces
	filename = strings.TrimSpace(filename)

	return filename
}

// EnsureUniqueFilename ensures a filename is unique by appending a number if needed
func EnsureUniqueFilename(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path // File doesn't exist, so path is unique
	}

	// File exists, append a number
	ext := filepath.Ext(path)
	basePath := path[:len(path)-len(ext)]

	for i := 1; i < 1000; i++ {
		newPath := fmt.Sprintf("%s_%d%s", basePath, i, ext)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
	}

	// If we get here, just use timestamp to ensure uniqueness
	return fmt.Sprintf("%s_%d%s", basePath, time.Now().UnixNano(), ext)
}
