package parser

import (
	"fmt"
	"net/mail"
	"strings"
)

// ParseEmailAddress parses an email address string into name and address components
func ParseEmailAddress(emailStr string) (name, address string) {
	if emailStr == "" {
		return "", ""
	}

	addr, err := mail.ParseAddress(emailStr)
	if err != nil {
		// If parsing fails, try to extract just the email part
		if start := strings.Index(emailStr, "<"); start != -1 {
			if end := strings.Index(emailStr[start:], ">"); end != -1 {
				address = emailStr[start+1 : start+end]
				name = strings.TrimSpace(emailStr[:start])
				return
			}
		}

		// If still no success, just return the original string as address
		return "", emailStr
	}

	return addr.Name, addr.Address
}

// FormatEmailAddress formats name and address into a standard email address string
func FormatEmailAddress(name, address string) string {
	if name == "" {
		return address
	}
	return fmt.Sprintf("%s <%s>", name, address)
}

// GetExtensionFromContentType returns a file extension for a content type
func GetExtensionFromContentType(contentType string) string {
	// Extract the main content type
	mainType := contentType
	if idx := strings.Index(contentType, ";"); idx != -1 {
		mainType = contentType[:idx]
	}
	mainType = strings.TrimSpace(strings.ToLower(mainType))

	// Check if we have a mapping for this content type
	if ext, ok := MimeToExt[mainType]; ok {
		return ext
	}

	// Default extension based on general type
	if strings.HasPrefix(mainType, "image/") {
		return ".img"
	} else if strings.HasPrefix(mainType, "text/") {
		return ".txt"
	} else if strings.HasPrefix(mainType, "audio/") {
		return ".audio"
	} else if strings.HasPrefix(mainType, "video/") {
		return ".video"
	}

	// Default fallback
	return ".bin"
}
