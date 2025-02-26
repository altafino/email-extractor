package parser

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// ParseHeaders parses email headers from a reader
func ParseHeaders(r io.Reader) (map[string][]string, error) {
	headers := make(map[string][]string)
	scanner := bufio.NewScanner(r)
	var currentKey string
	var currentValue string

	// Increase scanner buffer for large headers
	buf := make([]byte, 0, 64*1024) // 64KB buffer
	scanner.Buffer(buf, 1024*1024)  // Allow up to 1MB per line

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // End of headers
		}

		// Check if this is a continuation line
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// Continuation of previous header
			if currentKey != "" {
				currentValue += " " + strings.TrimSpace(line)
				// Update the last value for this key
				if len(headers[currentKey]) > 0 {
					headers[currentKey][len(headers[currentKey])-1] = currentValue
				}
			}
			continue
		}

		// New header line
		if idx := strings.Index(line, ":"); idx != -1 {
			// Save previous header if there was one
			if currentKey != "" && currentValue != "" {
				headers[currentKey] = append(headers[currentKey], currentValue)
			}

			// Start new header
			currentKey = strings.TrimSpace(line[:idx])
			currentValue = strings.TrimSpace(line[idx+1:])

			// Add to headers map
			if _, exists := headers[currentKey]; !exists {
				headers[currentKey] = []string{}
			}
		}
	}

	// Add the last header if there is one
	if currentKey != "" && currentValue != "" {
		headers[currentKey] = append(headers[currentKey], currentValue)
	}

	if err := scanner.Err(); err != nil {
		return headers, fmt.Errorf("error scanning headers: %w", err)
	}

	return headers, nil
}

// ExtractHeaderValue tries multiple header names to extract a value
func ExtractHeaderValue(headers map[string][]string, headerNames []string) string {
	for _, name := range headerNames {
		if values, ok := headers[name]; ok && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// ExtractDateValue extracts and parses date from headers
func ExtractDateValue(headers map[string][]string, logger *slog.Logger) time.Time {
	// Try multiple header names for date
	dateHeaderNames := []string{"Date", "DATE", "date", "Sent", "SENT", "sent"}
	dateStr := ExtractHeaderValue(headers, dateHeaderNames)

	if dateStr != "" {
		// Try various date formats
		dateFormats := []string{
			time.RFC1123Z,
			time.RFC1123,
			time.RFC822Z,
			time.RFC822,
			"Mon, 2 Jan 2006 15:04:05 -0700",
			"2 Jan 2006 15:04:05 -0700",
			"Mon, 2 Jan 2006 15:04:05 MST",
			"Mon, 2 Jan 2006 15:04:05",
		}

		for _, format := range dateFormats {
			if parsedTime, err := time.Parse(format, dateStr); err == nil {
				logger.Debug("successfully parsed date",
					"date_string", dateStr,
					"format", format,
					"parsed_time", parsedTime)
				return parsedTime
			}
		}

		logger.Debug("failed to parse date with any format", "date_string", dateStr)
	} else {
		logger.Debug("no date header found")
	}

	// If we can't parse the date, use current time
	return time.Now().UTC()
}
