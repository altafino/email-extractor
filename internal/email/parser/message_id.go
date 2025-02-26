package parser

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strings"
)

// GenerateUniqueMessageID generates a unique ID for a message
func GenerateUniqueMessageID(msgContent []byte) string {
	// Try to extract Message-ID header from content
	messageIDHeader := ExtractMessageIDHeader(msgContent)
	if messageIDHeader != "" {
		return messageIDHeader
	}

	// If no Message-ID header, generate MD5 hash of content
	hash := md5.Sum(msgContent)
	return hex.EncodeToString(hash[:])
}

// ExtractMessageIDHeader extracts Message-ID header from email content
func ExtractMessageIDHeader(content []byte) string {
	// Simple implementation to extract Message-ID header
	lines := bytes.Split(content, []byte("\n"))
	for _, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("message-id:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				// Clean up the Message-ID value
				id := string(bytes.TrimSpace(parts[1]))
				// Remove any < > brackets if present
				id = strings.Trim(id, "<>")
				return id
			}
		}
	}
	return ""
}
