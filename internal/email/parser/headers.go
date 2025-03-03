package parser

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode"
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
	// Try multiple header names for date - expanded list
	dateHeaderNames := []string{
		"Date", "DATE", "date",
		"Sent", "SENT", "sent",
		"Delivery-Date", "delivery-date",
		"Received", "RECEIVED", "received",
		"Resent-Date", "resent-date",
		"Original-Date", "original-date",
		"X-Date", "x-date",
		"X-Original-Date", "x-original-date",
		"X-Received", "x-received",
		"X-Resent-Date", "x-resent-date",
		"X-Original-Received", "x-original-received",
		"X-Original-Resent-Date", "x-original-resent-date",
		"X-Original-Date", "x-original-date",
		"X-Original-Date", "x-original-date",
		// Portuguese headers
		"Data", "DATA", "data",
		"Enviado", "ENVIADO", "enviado",
		"Recebido", "RECEBIDO", "recebido",
		"Reenviado", "REENVIADO", "reenviado",
		"Original-Data", "original-data",
		"Data-Envio", "data-envio",
		"Data-Recebimento", "data-recebimento",
		"Data-Reenvio", "data-reenvio",
		"Data-Original", "data-original",
		"Data-X", "data-x",
		"Data-X-Original", "data-x-original",
		"Data-X-Received", "data-x-received",
		"Data-X-Resent-Date", "data-x-resent-date",
		"Data-X-Original-Received", "data-x-original-received",
		"Data-X-Original-Resent-Date", "data-x-original-resent-date",
		"Data-X-Original-Date", "data-x-original-date",
		"Data-X-Original-Date", "data-x-original-date",
	}

	// Try each header name
	var dateStr string
	var headerUsed string
	for _, name := range dateHeaderNames {
		if values, ok := headers[name]; ok && len(values) > 0 {
			// For "Received" header, extract the date part
			if strings.EqualFold(name, "Received") {
				parts := strings.Split(values[0], ";")
				if len(parts) > 1 {
					dateStr = strings.TrimSpace(parts[len(parts)-1])
				} else {
					dateStr = values[0]
				}
			} else {
				dateStr = values[0]
			}

			headerUsed = name
			if dateStr != "" {
				break
			}
		}
	}

	if dateStr != "" {
		logger.Debug("found date header", "header", headerUsed, "value", dateStr)

		// Clean up the date string
		dateStr = strings.TrimSpace(dateStr)

		// Try various date formats - expanded list including Brazilian formats
		dateFormats := []string{
			// Standard formats
			time.RFC1123Z,
			time.RFC1123,
			time.RFC822Z,
			time.RFC822,
			time.RFC3339,
			time.RFC850,
			time.ANSIC,
			time.UnixDate,
			time.RFC3339Nano,
			"Mon, 2 Jan 2006 15:04:05 -0700",
			"Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
			"Mon, 2 Jan 2006 15:04:05 MST",
			"Mon, 2 Jan 2006 15:04:05",
			"2 Jan 2006 15:04:05 -0700",
			"2 Jan 2006 15:04:05 MST",
			"2 Jan 2006 15:04:05",
			"Mon, 02 Jan 2006 15:04:05 -0700",
			"Mon, 02 Jan 06 15:04:05 -0700",
			"Mon, 02 Jan 06 15:04:05 MST",
			"Mon Jan 02 15:04:05 2006",
			"Mon Jan 2 15:04:05 2006",
			"Jan 2 15:04:05 2006",

			// Brazilian date formats
			"02/01/2006",                     // DD/MM/YYYY
			"02/01/2006 15:04:05",            // DD/MM/YYYY HH:MM:SS
			"02/01/2006 15:04",               // DD/MM/YYYY HH:MM
			"02-01-2006",                     // DD-MM-YYYY
			"02-01-2006 15:04:05",            // DD-MM-YYYY HH:MM:SS
			"02-01-2006 15:04",               // DD-MM-YYYY HH:MM
			"02 de January de 2006",          // DD de Month de YYYY (English)
			"02 de January de 2006 15:04:05", // DD de Month de YYYY HH:MM:SS (English)
			"02 de January de 2006 15:04",    // DD de Month de YYYY HH:MM (English)
			"02 de Janeiro de 2006",          // DD de Month de YYYY (Portuguese)
			"02 de Janeiro de 2006 15:04:05", // DD de Month de YYYY HH:MM:SS (Portuguese)
			"02 de Janeiro de 2006 15:04",    // DD de Month de YYYY HH:MM (Portuguese)
			"02 de Jan de 2006",              // DD de Month abbreviation de YYYY (Portuguese/English mix)
			"02 de Jan de 2006 15:04:05",     // DD de Month abbreviation de YYYY HH:MM:SS
			"02 de Jan de 2006 15:04",        // DD de Month abbreviation de YYYY HH:MM

			// Additional variations:

			"02/01/2006 03:04:05 PM", // DD/MM/YYYY hh:MM:SS AM/PM (12-hour)
			"02/01/2006 03:04 PM",    // DD/MM/YYYY hh:MM AM/PM (12-hour)
			"02-01-2006 03:04:05 PM", // DD-MM-YYYY hh:MM:SS AM/PM (12-hour)
			"02-01-2006 03:04 PM",    // DD-MM-YYYY hh:MM AM/PM (12-hour)

			"02/01/2006 15:04:05 -0300",            // DD/MM/YYYY HH:MM:SS with timezone offset
			"02-01-2006 15:04 -0300",               // DD-MM-YYYY HH:MM with timezone offset
			"02 de Janeiro de 2006 15:04:05 -0300", // DD de Month de YYYY HH:MM:SS with timezone offset
			"02 de Jan de 2006 15:04 -0300",        // DD de Month abbreviation de YYYY HH:MM with timezone offset

			"terça-feira, 02/01/2006",                  // Weekday, DD/MM/YYYY (Portuguese weekday)
			"terça-feira, 02/01/2006 15:04:05",         // Weekday, DD/MM/YYYY HH:MM:SS
			"terça-feira, 02 de Janeiro de 2006",       // Weekday, DD de Month de YYYY (Portuguese)
			"terça-feira, 02 de Janeiro de 2006 15:04", // Weekday, DD de Month de YYYY HH:MM

			"02.01.2006",          // DD.MM.YYYY (dot-separated)
			"02.01.2006 15:04:05", // DD.MM.YYYY HH:MM:SS
			"02.01.2006 15:04",    // DD.MM.YYYY HH:MM

			"Sex, 02 Jan 2006 15:04:05 -0300",                   // RFC style with abbreviated day (English)
			"sexta-feira, 02 de Janeiro de 2006 15:04:05 -0300", // Weekday, DD de Month de YYYY HH:MM:SS with timezone offset (Portuguese)
			// ("Sex" may also be "sexta-feira," depending on localization)
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

		// Try to handle dates with timezone names in parentheses
		if strings.Contains(dateStr, "(") && strings.Contains(dateStr, ")") {
			cleanDateStr := strings.Split(dateStr, "(")[0]
			cleanDateStr = strings.TrimSpace(cleanDateStr)

			for _, format := range dateFormats {
				if parsedTime, err := time.Parse(format, cleanDateStr); err == nil {
					logger.Debug("successfully parsed date after removing parentheses",
						"original", dateStr,
						"cleaned", cleanDateStr,
						"format", format,
						"parsed_time", parsedTime)
					return parsedTime
				}
			}
		}

		logger.Debug("failed to parse date with any format", "date_string", dateStr)
	} else {
		// Log all available headers to help diagnose the issue
		var headerKeys []string
		for k := range headers {
			headerKeys = append(headerKeys, k)
		}
		logger.Debug("no date header found", "available_headers", strings.Join(headerKeys, ", "), "headers", headers)
	}

	// If we can't parse the date, use current time
	return time.Now().UTC()
}

// containsDigitsAndLetters checks if a string contains both digits and letters
// which is a good heuristic for identifying date strings
func containsDigitsAndLetters(s string) bool {
	hasDigit := false
	hasLetter := false

	for _, r := range s {
		if unicode.IsDigit(r) {
			hasDigit = true
		} else if unicode.IsLetter(r) {
			hasLetter = true
		}

		if hasDigit && hasLetter {
			return true
		}
	}

	return false
}
