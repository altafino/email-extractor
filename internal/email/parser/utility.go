package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/DusanKasan/parsemail"
	"github.com/jhillyerd/enmime/mediatype"
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

// ProcessEmailContent prepares and repairs email content for parsing
func ProcessEmailContent(content []byte, messageID string, logger *slog.Logger) ([]byte, string, []parsemail.Attachment, error) {
	// Try to find the boundary in the content
	boundary := DetectBoundary(content, 1000)

	if boundary == "" {
		// Try to find boundary marker directly
		for _, line := range bytes.Split(content[:min(1000, len(content))], []byte("\n")) {
			if bytes.HasPrefix(bytes.TrimSpace(line), []byte("--")) {
				potentialBoundary := string(bytes.TrimSpace(line)[2:])
				// Verify this boundary appears multiple times
				if bytes.Count(content, []byte("--"+potentialBoundary)) > 1 {
					boundary = potentialBoundary
					break
				}
			}
		}
	}

	// Add missing headers if needed
	if !bytes.Contains(content[:min(100, len(content))], []byte("From:")) {
		content = AddMissingHeaders(content, boundary)
	}

	// Fix malformed boundaries
	content = FixMalformedBoundaries(content)

	// Log first few bytes of the message to help debug
	preview := min(len(content), 200)
	logger.Debug("message preview",
		"message_id", messageID,
		"content", string(content[:preview]))

	// Extract Content-Type and boundary from headers
	var attachments []parsemail.Attachment
	headers, _ := ParseHeaders(bytes.NewReader(content))

	if contentType, ok := headers["Content-Type"]; ok && len(contentType) > 0 {
		// Clean up Content-Type header
		cleanContentType := contentType[0]

		logger.Debug("processing email content type",
			"message_id", messageID,
			"raw_content_type", contentType[0],
			"clean_content_type", cleanContentType)

		// Extract boundary from Content-Type
		mediaType, params, _, err := mediatype.Parse(cleanContentType)
		if err != nil {
			logger.Debug("failed to parse media type",
				"message_id", messageID,
				"error", err,
				"raw_content_type", contentType[0],
				"clean_content_type", cleanContentType)

			// Try to clean up Content-Type more aggressively for parsing
			cleanContentType = strings.ReplaceAll(cleanContentType, `"`, "")
			cleanContentType = strings.ReplaceAll(cleanContentType, `'`, "")
			cleanContentType = strings.TrimSpace(cleanContentType)
			// Try parsing again with cleaned content type
			mediaType, params, _, err = mediatype.Parse(cleanContentType)
			if err == nil {
				logger.Debug("successfully parsed media type after cleanup",
					"message_id", messageID,
					"clean_content_type", cleanContentType)
			}
		}

		if err == nil && strings.HasPrefix(mediaType, "multipart/") {
			if boundaryParam, ok := params["boundary"]; ok {
				logger.Debug("found boundary in headers",
					"message_id", messageID,
					"boundary", boundaryParam,
					"media_type", mediaType,
					"all_params", params)

				// Try to find actual boundary marker in content
				actualBoundary := FindActualBoundary(content, boundaryParam, logger, messageID)

				// Use actual boundary if found, otherwise use the one from headers
				if actualBoundary != "" {
					boundary = actualBoundary
				} else {
					boundary = boundaryParam
				}

				// Try multipart parser with the boundary
				attachments, err = ExtractAttachmentsMultipart(content, boundary, logger)
				if err != nil {
					boundaryMarker := []byte("--" + boundary)
					crlfBoundaryMarker := []byte("\r\n--" + boundary)

					logger.Debug("failed to extract attachments with multipart parser",
						"error", err,
						"message_id", messageID,
						"boundary", boundary,
						"content_length", len(content),
						"boundary_count", bytes.Count(content, boundaryMarker),
						"crlf_boundary_count", bytes.Count(content, crlfBoundaryMarker))
				}
			}
		}
	}

	// If multipart parsing failed, try parsemail as fallback
	if len(attachments) == 0 {
		email, err := ParseEmail(content, logger)
		if err != nil {
			return content, boundary, nil, fmt.Errorf("failed to parse email: %w", err)
		}

		attachments = append(attachments, email.Attachments...)
		for _, ef := range email.EmbeddedFiles {
			attachments = append(attachments, parsemail.Attachment{
				Filename: fmt.Sprintf("embedded_%d%s", time.Now().UnixNano(), GetExtensionFromContentType(ef.ContentType)),
				Data:     ef.Data,
			})
		}
	}

	return content, boundary, attachments, nil
}

// FindActualBoundary searches for actual boundary markers in the content
func FindActualBoundary(content []byte, headerBoundary string, logger *slog.Logger, messageID string) string {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Increase scanner buffer for large HTML content
	buf := make([]byte, 0, 64*1024) // 64KB buffer
	scanner.Buffer(buf, 1024*1024)  // Allow up to 1MB per line

	var foundBoundaries []string
	var allLines []string // Store all lines for debugging

	for scanner.Scan() {
		line := scanner.Text()
		allLines = append(allLines, line)

		if strings.HasPrefix(line, "--") {
			potentialBoundary := strings.TrimPrefix(line, "--")
			potentialBoundary = strings.TrimSpace(potentialBoundary)
			if strings.HasSuffix(potentialBoundary, "--") {
				potentialBoundary = strings.TrimSuffix(potentialBoundary, "--")
			}

			foundBoundaries = append(foundBoundaries, potentialBoundary)
			logger.Debug("found potential boundary",
				"message_id", messageID,
				"boundary", potentialBoundary,
				"line", line)

			// Count occurrences of this boundary
			if bytes.Count(content, []byte("--"+potentialBoundary)) > 1 {
				return potentialBoundary
			}
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		logger.Debug("scanner error",
			"message_id", messageID,
			"error", err)
	}

	logger.Debug("boundary search results",
		"message_id", messageID,
		"header_boundary", headerBoundary,
		"found_boundaries", foundBoundaries,
		"content_lines", allLines[:min(10, len(allLines))], // Show first 10 lines
		"actual_boundary", "")

	// Check if this is a delivery status notification (DSN)
	for _, line := range allLines {
		if strings.HasPrefix(line, "Reporting-MTA:") {
			logger.Debug("detected DSN message", "message_id", messageID)
			return ""
		}
	}

	return ""
}

// GetRawMessageSample returns a sample of the raw message for debugging
func GetRawMessageSample(content []byte, maxSize int) string {
	if len(content) == 0 {
		return ""
	}

	if maxSize <= 0 {
		return ""
	}

	// If content is smaller than maxSize, return it all
	if len(content) <= maxSize {
		return string(content)
	}

	// Otherwise return the first part
	return string(content[:maxSize])
}

// Min returns the smaller of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the larger of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
