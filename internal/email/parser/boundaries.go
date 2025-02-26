package parser

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// DetectBoundary tries to find the MIME boundary in email content
func DetectBoundary(content []byte, maxLines int) string {
	// Try to find the boundary in the content
	lines := bytes.Split(content[:min(len(content), maxLines*100)], []byte("\n"))

	// First look for Content-Type header with boundary
	for _, line := range lines[:min(len(lines), maxLines)] {
		if bytes.Contains(bytes.ToLower(line), []byte("boundary=")) {
			if idx := bytes.Index(line, []byte("boundary=")); idx != -1 {
				boundary := string(bytes.Trim(line[idx+9:], `"' `))
				// Sometimes boundary is part of Content-Type, extract just the boundary part
				if idx := strings.Index(boundary, ";"); idx != -1 {
					boundary = strings.Trim(boundary[:idx], `"' `)
				}
				return boundary
			}
		}
	}

	// If not found in headers, try to find boundary marker directly
	for _, line := range lines {
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte("--")) {
			potentialBoundary := string(bytes.TrimSpace(line)[2:])
			// Verify this boundary appears multiple times
			if bytes.Count(content, []byte("--"+potentialBoundary)) > 1 {
				return potentialBoundary
			}
		}
	}

	return ""
}

// CleanupBoundary cleans up a boundary string
func CleanupBoundary(boundary string) string {
	// Clean up boundary - remove any extra quotes or invalid characters
	boundary = strings.Trim(boundary, `"'`)
	boundary = strings.TrimSuffix(boundary, `\`)
	boundary = strings.TrimSpace(boundary)
	return boundary
}

// AddMissingHeaders adds basic email headers if they're missing
func AddMissingHeaders(content []byte, boundary string) []byte {
	// Check if headers are already present
	if bytes.Contains(content[:min(100, len(content))], []byte("From:")) {
		return content
	}

	// Clean up boundary if provided
	boundaryToUse := boundary
	if boundaryToUse == "" {
		boundaryToUse = fmt.Sprintf("_%x", time.Now().UnixNano())
	} else {
		boundaryToUse = CleanupBoundary(boundaryToUse)
	}

	// Add basic email headers
	headers := []byte("From: unknown@example.com\r\n" +
		"To: unknown@example.com\r\n" +
		"Subject: No Subject\r\n" +
		"MIME-Version: 1.0\r\n" +
		fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n\r\n", boundaryToUse))

	return append(headers, content...)
}

// FixMalformedBoundaries fixes common issues with boundary declarations
func FixMalformedBoundaries(content []byte) []byte {
	// Fix common Brazilian email client boundary formats
	content = bytes.ReplaceAll(content,
		[]byte(`boundary="_000_`),
		[]byte(`boundary="`))
	content = bytes.ReplaceAll(content,
		[]byte(`_LAMP_"`),
		[]byte(`"`))
	content = bytes.ReplaceAll(content,
		[]byte(`boundary="----=_NextPart`),
		[]byte(`boundary="NextPart`))
	content = bytes.ReplaceAll(content,
		[]byte(`boundary="------=_NextPart`),
		[]byte(`boundary="NextPart`))
	content = bytes.ReplaceAll(content,
		[]byte(`boundary="------=_Part`),
		[]byte(`boundary="Part`))

	// Fix malformed Content-Type headers in the content
	content = bytes.ReplaceAll(content,
		[]byte(`boundary=\"`),
		[]byte(`boundary=`))
	content = bytes.ReplaceAll(content,
		[]byte(`\"\r\n`),
		[]byte(`\r\n`))
	content = bytes.ReplaceAll(content,
		[]byte(`boundary==`),
		[]byte(`boundary=`))

	// Clean up any remaining invalid quotes in boundaries
	if idx := bytes.Index(content, []byte("boundary=")); idx != -1 {
		endIdx := bytes.Index(content[idx:], []byte("\r\n"))
		if endIdx != -1 {
			headerPart := content[idx : idx+endIdx]
			cleanHeader := bytes.ReplaceAll(headerPart, []byte(`"`), []byte(``))
			// Remove any remaining special characters
			cleanHeader = bytes.Map(func(r rune) rune {
				if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '=' {
					return r
				}
				return -1
			}, cleanHeader)
			newContent := make([]byte, len(content))
			copy(newContent, content)
			copy(newContent[idx:idx+endIdx], cleanHeader)
			content = newContent
		}
	}

	return content
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
