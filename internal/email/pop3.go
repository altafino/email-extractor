package email

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jhillyerd/enmime/mediatype"
	"github.com/DusanKasan/parsemail"
	"github.com/altafino/email-extractor/internal/models"
	"github.com/altafino/email-extractor/internal/tracking"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/knadh/go-pop3"
)

type POP3Client struct {
	cfg    *types.Config
	logger *slog.Logger
}

// Map of common MIME types to file extensions
var mimeToExt = map[string]string{
	"image/jpeg":               ".jpg",
	"image/jpg":                ".jpg",
	"image/png":                ".png",
	"image/gif":                ".gif",
	"application/pdf":          ".pdf",
	"application/xml":          ".xml",
	"text/xml":                 ".xml",
	"application/vnd.ms-excel": ".xls",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
	"application/msword": ".doc",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   ".docx",
	"application/vnd.ms-powerpoint":                                             ".ppt",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
	"text/plain":                   ".txt",
	"text/csv":                     ".csv",
	"application/zip":              ".zip",
	"application/x-zip-compressed": ".zip",
	"application/x-rar-compressed": ".rar",
	"application/x-7z-compressed":  ".7z",
	"application/rtf":              ".rtf",
	"application/octet-stream":     ".bin",
	"application/x-compressed":     ".tar",
	"application/x-gzip":           ".gz",
	"application/x-bzip2":          ".bz2",
	"application/x-tar":            ".tar",
	"application/x-7zip-compressed": ".7z",
	"application/x-compressed-tar": ".tar.gz",
	"application/x-compressed-zip": ".zip.gz",
	"application/x-compressed-bz2": ".bz2.gz",
	"application/x-compressed-7z": ".7z.gz",
	"application/x-compressed-rar": ".rar.gz",
	
	
}

func NewPOP3Client(cfg *types.Config, logger *slog.Logger) *POP3Client {
	return &POP3Client{
		cfg:    cfg,
		logger: logger,
	}
}

func (c *POP3Client) Connect(emailCfg models.EmailConfig) (*pop3.Conn, error) {
	// Obfuscate password for logging
	obfuscatedPassword := "********"

	c.logger.Info("connecting to POP3 server",
		"server", emailCfg.Server,
		"port", emailCfg.Port,
		"tls_enabled", emailCfg.EnableTLS,
		"username", emailCfg.Username,
		"password", obfuscatedPassword, // Use obfuscated password in logs
		"tls_skip_verify", !c.cfg.Email.Protocols.POP3.Security.TLS.VerifyCert,
		"tls_config", c.cfg.Email.Protocols.POP3.Security.TLS,
	)

	// Initialize POP3 client
	p := pop3.New(pop3.Opt{
		Host:          emailCfg.Server,
		Port:          emailCfg.Port,
		TLSEnabled:    emailCfg.EnableTLS,
		TLSSkipVerify: !c.cfg.Email.Protocols.POP3.Security.TLS.VerifyCert,
	})

	// Create new connection
	conn, err := p.NewConn()
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Authenticate - use the actual password here, not the obfuscated one
	if err := conn.Auth(emailCfg.Username, emailCfg.Password); err != nil {
		conn.Quit()
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	c.logger.Info("successfully connected to POP3 server")
	return conn, nil
}

func decodeContent(content []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "base64":
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(content)))
		n, err := base64.StdEncoding.Decode(decoded, content)
		if err != nil {
			return nil, err
		}
		return decoded[:n], nil

	case "quoted-printable":
		reader := quotedprintable.NewReader(bytes.NewReader(content))
		return io.ReadAll(reader)

	case "7bit", "8bit", "binary", "":
		return content, nil

	default:
		return content, nil
	}
}

// decodeFilename decodes RFC 2047 encoded-word syntax in filenames
func decodeFilename(filename string) string {
	decoder := mime.WordDecoder{}
	decoded, err := decoder.DecodeHeader(filename)
	if err != nil {
		// If decoding fails, return the original filename
		return filename
	}
	return decoded
}

func (c *POP3Client) extractAttachmentsMultipart(content []byte, boundary string) ([]parsemail.Attachment, error) {
	// Skip preamble and find first boundary
	boundaryBytes := []byte("--" + boundary)
	if idx := bytes.Index(content, boundaryBytes); idx != -1 {
		content = content[idx:]
	}

	// Function to handle nested multipart content
	var handleMultipart func([]byte, string) ([]parsemail.Attachment, error)
	handleMultipart = func(content []byte, boundary string) ([]parsemail.Attachment, error) {
		var nestedAttachments []parsemail.Attachment
		var currentPart []byte
		var inHeader bool = true
		var headers map[string][]string = make(map[string][]string)

		parts := bytes.Split(content, boundaryBytes)
		for _, part := range parts[1:] { // Skip the first empty part
			if bytes.HasPrefix(part, []byte("--")) {
				break // End boundary
			}

			// Split headers and body
			lines := bytes.Split(bytes.TrimSpace(part), []byte("\n"))
			inHeader = true
			headers = make(map[string][]string)
			currentPart = nil
			var bodyStart int

			for i, line := range lines {
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					inHeader = false
					bodyStart = i + 1
					continue
				}

				if inHeader {
					if idx := bytes.Index(line, []byte(":")); idx > 0 {
						key := string(bytes.TrimSpace(line[:idx]))
						value := string(bytes.TrimSpace(line[idx+1:]))
						headers[key] = append(headers[key], value)
					}
				}
			}

			// Join body lines with original line endings
			if bodyStart < len(lines) {
				currentPart = bytes.Join(lines[bodyStart:], []byte("\n"))
			}

			// Process the part based on headers
			contentType := ""
			if ct, ok := headers["Content-Type"]; ok && len(ct) > 0 {
				contentType = ct[0]
			}

			//mediaType, params, err := mime.ParseMediaType(contentType)
			mediaType, params,invalidParams, err := mediatype.Parse(contentType)
			c.logger.Debug("mediaType", "mediaType", mediaType, "params", params, "invalidParams", invalidParams, "err", err)
			if err == nil {
				// Handle nested multipart
				if strings.Contains(strings.ToLower(mediaType), "multipart") {
					if nestedBoundary := params["boundary"]; nestedBoundary != "" {
						// Clean up nested content before processing
						if idx := bytes.Index(currentPart, []byte("--"+nestedBoundary)); idx != -1 {
							currentPart = currentPart[idx:]
						}
						nested, err := handleMultipart(currentPart, nestedBoundary)
						if err == nil {
							nestedAttachments = append(nestedAttachments, nested...)
						}
						continue
					}
				}

				// Check for attachment
				contentDisp := ""
				if cd, ok := headers["Content-Disposition"]; ok && len(cd) > 0 {
					contentDisp = cd[0]
				}

				filename := ""
				if contentDisp != "" {
					if _, params, _, err := mediatype.Parse(contentDisp); err == nil {
						if fn, ok := params["filename"]; ok {
							filename = decodeFilename(fn)
						}
					}
				}

				// If no filename from disposition, try Content-Type name parameter
				if filename == "" && params["name"] != "" {
					filename = decodeFilename(params["name"])
				}

				// Determine if this part is an attachment
				isAttachment := false
				if contentDisp != "" {
					isAttachment = strings.Contains(contentDisp, "attachment") || strings.Contains(contentDisp, "inline")
				} else {
					isAttachment = strings.HasPrefix(mediaType, "application/") ||
						strings.HasPrefix(mediaType, "image/") ||
						strings.Contains(mediaType, "pdf") ||
						strings.Contains(mediaType, "xml") ||
						strings.Contains(mediaType, "msword") ||
						strings.Contains(mediaType, "excel") ||
						strings.Contains(mediaType, "spreadsheet") ||
						strings.Contains(mediaType, "document") ||
						strings.Contains(mediaType, "text") ||
						strings.Contains(mediaType, "audio") ||
						strings.Contains(mediaType, "video") ||
						strings.Contains(mediaType, "application") ||
						strings.Contains(mediaType, "zip") ||
						strings.Contains(mediaType, "tar") ||
						strings.Contains(mediaType, "gz") ||
						strings.Contains(mediaType, "bz2") ||
						strings.Contains(mediaType, "7z") ||
						strings.Contains(mediaType, "rar")
				}

				if isAttachment && len(currentPart) > 0 {
					// Trim any trailing boundary markers
					if idx := bytes.Index(currentPart, []byte("\n--")); idx != -1 {
						currentPart = currentPart[:idx]
					}

					// Handle content encoding
					if ce, ok := headers["Content-Transfer-Encoding"]; ok && len(ce) > 0 {
						decoded, err := decodeContent(currentPart, ce[0])
						if err == nil {
							currentPart = decoded
						}
					}

					// Generate filename if needed
					if filename == "" {
						ext := ".bin"
						if mimeExt, ok := mimeToExt[mediaType]; ok {
							ext = mimeExt
						}
						// Just use a simple base name for attachments without names
						filename = fmt.Sprintf("attachment%s", ext)
					} else {
						// For existing filenames, just trim spaces
						filename = strings.TrimSpace(filename)
					}

					nestedAttachments = append(nestedAttachments, parsemail.Attachment{
						Filename: filename,
						Data:     bytes.NewReader(currentPart),
					})
				}
			}
		}
		return nestedAttachments, nil
	}

	slog.Debug("starting multipart extraction", "boundary", boundary)
	return handleMultipart(content, boundary)
}

func parseHeaders(r io.Reader) (map[string][]string, error) {
	headers := make(map[string][]string)
	scanner := bufio.NewScanner(r)
	var currentKey string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // End of headers
		}

		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// Continuation of previous header
			if currentKey != "" {
				headers[currentKey][len(headers[currentKey])-1] += " " + strings.TrimSpace(line)
			}
			continue
		}

		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			currentKey = key
			headers[key] = append(headers[key], value)
		}
	}

	return headers, scanner.Err()
}

// Simplify the function to only use the message content
func (c *POP3Client) generateUniqueMessageID(msgContent []byte) string {
	// Try to extract Message-ID header from content
	messageIDHeader := extractMessageIDHeader(msgContent)
	if messageIDHeader != "" {
		return messageIDHeader
	}

	// If no Message-ID header, generate MD5 hash of content
	hash := md5.Sum(msgContent)
	return hex.EncodeToString(hash[:])
}

// Extract Message-ID header from email content
func extractMessageIDHeader(content []byte) string {
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

func (c *POP3Client) DownloadEmails(req models.EmailDownloadRequest) ([]models.DownloadResult, error) {
	c.logger.Info("starting email download")

	// Create tracking manager
	trackingManager, err := tracking.NewManager(c.cfg, c.logger)
	if err != nil {
		c.logger.Error("failed to initialize tracking manager", "error", err)
		// Continue without tracking if it fails
	} else {
		defer trackingManager.Close()
	}

	conn, err := c.Connect(req.Config)
	if err != nil {
		return nil, err
	}
	defer conn.Quit()

	// Get message count
	count, size, err := conn.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get mailbox stats: %w", err)
	}

	c.logger.Info("mailbox stats",
		"messages", count,
		"total_size", size,
	)

	var results []models.DownloadResult

	// Get list of all messages
	msgList, err := conn.List(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}

	for _, popMsg := range msgList {
		// Check if this message has already been downloaded
		if trackingManager != nil && c.cfg.Email.Tracking.TrackDownloaded {
			downloaded, err := trackingManager.IsEmailDownloaded(
				req.Config.Protocol,
				req.Config.Server,
				req.Config.Username,
				fmt.Sprintf("%d", popMsg.ID),
			)
			if err != nil {
				c.logger.Warn("failed to check if email was downloaded",
					"message_id", popMsg.ID,
					"error", err)
				// Continue processing this message
			} else if downloaded {
				c.logger.Debug("skipping already downloaded message", "message_id", popMsg.ID)
				continue // Skip this message
			}
		}

		result := models.DownloadResult{
			MessageID:    fmt.Sprintf("%d", popMsg.ID),
			DownloadedAt: time.Now().UTC(),
			Status:       "processing",
		}

		// Get message
		msgReader, err := conn.Retr(popMsg.ID)
		if err != nil {
			c.logger.Debug("failed to retrieve message", "error", err, "message_id", popMsg.ID)
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to retrieve message: %v", err)
			results = append(results, result)
			continue
		}

		c.logger.Debug("retrieved message", "message_id", popMsg.ID)

		// Buffer the message body for multiple reads
		buf := bytes.NewBuffer([]byte{})
		_, err = io.Copy(buf, msgReader.Body)
		if err != nil {
			c.logger.Debug("failed to buffer message", "error", err, "message_id", popMsg.ID)
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to buffer message: %v", err)
			results = append(results, result)
			continue
		}

		c.logger.Debug("message size", "bytes", buf.Len(), "message_id", popMsg.ID)

		// Get message content
		content := buf.Bytes()

		// Generate a unique message ID
		uniqueID := c.generateUniqueMessageID(content)

		// Check if this message has already been downloaded using the unique ID
		if trackingManager != nil && c.cfg.Email.Tracking.TrackDownloaded {
			downloaded, err := trackingManager.IsEmailDownloaded(
				req.Config.Protocol,
				req.Config.Server,
				req.Config.Username,
				uniqueID,
			)
			if err != nil {
				c.logger.Warn("failed to check if email was downloaded",
					"message_id", uniqueID,
					"error", err)
				// Continue processing this message
			} else if downloaded {
				c.logger.Debug("skipping already downloaded message", "message_id", uniqueID)
				continue // Skip this message
			}
		}

		// Check if we need to add headers
		var boundary string

		// Try to find the actual boundary in the content
		lines := bytes.Split(content[:min(1000, len(content))], []byte("\n"))
		for _, line := range lines {
			if bytes.Contains(bytes.ToLower(line), []byte("boundary=")) {
				if idx := bytes.Index(line, []byte("boundary=")); idx != -1 {
					boundary = string(bytes.Trim(line[idx+9:], `"' `))
					// Sometimes boundary is part of Content-Type, extract just the boundary part
					if idx := strings.Index(boundary, ";"); idx != -1 {
						boundary = strings.Trim(boundary[:idx], `"' `)
					}
					break
				}
			}
		}

		if boundary == "" {
			// Try to find boundary marker directly
			for _, line := range lines {
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

		if !bytes.Contains(content[:min(100, len(content))], []byte("From:")) {
			// Add basic email headers if they're missing
			boundaryToUse := boundary
			if boundaryToUse == "" {
				boundaryToUse = fmt.Sprintf("_%x", time.Now().UnixNano())
			} else {
				// Clean up boundary - remove any extra quotes or invalid characters
				boundaryToUse = strings.Trim(boundaryToUse, `"'`)
				boundaryToUse = strings.TrimSuffix(boundaryToUse, `\`)
				boundaryToUse = strings.TrimSpace(boundaryToUse)
			}
			headers := []byte("From: unknown@example.com\r\n" +
				"To: unknown@example.com\r\n" +
				"Subject: No Subject\r\n" +
				"MIME-Version: 1.0\r\n" +
				fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n\r\n", boundaryToUse))
			content = append(headers, content...)

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
					copy(content[idx:idx+endIdx], cleanHeader)
				}
			}
		}

		// Log first few bytes of the message to help debug
		preview := min(len(content), 200)
		c.logger.Debug("message preview",
			"message_id", popMsg.ID,
			"content", string(content[:preview]))

		// Extract Content-Type and boundary from headers
		var attachments []parsemail.Attachment
		headers, _ := parseHeaders(bytes.NewReader(content))
		if contentType, ok := headers["Content-Type"]; ok && len(contentType) > 0 {
			// Clean up Content-Type header
			cleanContentType := contentType[0]
			// Log raw message preview for debugging
			previewLen := min(200, len(content))
			c.logger.Debug("raw message preview",
				"message_id", popMsg.ID,
				"preview", string(content[:previewLen]),
				"total_length", len(content))

			c.logger.Debug("processing email content type",
				"message_id", popMsg.ID,
				"raw_content_type", contentType[0],
				"clean_content_type", cleanContentType)

			// Extract boundary from Content-Type
			mediaType, params, _, err := mediatype.Parse(cleanContentType)
			if err != nil {
				c.logger.Debug("failed to parse media type",
					"message_id", popMsg.ID,
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
					c.logger.Debug("successfully parsed media type after cleanup",
						"message_id", popMsg.ID,
						"clean_content_type", cleanContentType)
				}
			}

			if err == nil && strings.HasPrefix(mediaType, "multipart/") {
				if boundary, ok := params["boundary"]; ok {
					c.logger.Debug("found boundary in headers",
						"message_id", popMsg.ID,
						"boundary", boundary,
						"media_type", mediaType,
						"all_params", params)

					// Try to find actual boundary marker in content
					var actualBoundary string
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
							c.logger.Debug("found potential boundary",
								"message_id", popMsg.ID,
								"boundary", potentialBoundary,
								"line", line)

							// Count occurrences of this boundary
							if bytes.Count(content, []byte("--"+potentialBoundary)) > 1 {
								actualBoundary = potentialBoundary
								break
							}
						}
					}
					// Check for scanner errors
					if err := scanner.Err(); err != nil {
						c.logger.Debug("scanner error",
							"message_id", popMsg.ID,
							"error", err)
					}

					c.logger.Debug("boundary search results",
						"message_id", popMsg.ID,
						"header_boundary", boundary,
						"found_boundaries", foundBoundaries,
						"content_lines", allLines[:min(10, len(allLines))], // Show first 10 lines
						"actual_boundary", actualBoundary)

					// Check if this is a delivery status notification (DSN)
					isDSN := false
					for _, line := range allLines {
						if strings.HasPrefix(line, "Reporting-MTA:") {
							isDSN = true
							break
						}
					}

					if isDSN {
						c.logger.Debug("skipping DSN message",
							"message_id", popMsg.ID)
						continue
					}

					// Use actual boundary if found, otherwise use the one from headers
					if actualBoundary != "" {
						boundary = actualBoundary
					}

					// Try our multipart parser with original content
					// Log first 100 bytes around each boundary marker
					boundaryMarker := []byte("--" + boundary)
					idx := bytes.Index(content, boundaryMarker)
					if idx != -1 {
						start := max(0, idx-50)
						end := min(len(content), idx+len(boundaryMarker)+50)
						c.logger.Debug("boundary context",
							"message_id", popMsg.ID,
							"boundary", boundary,
							"context", string(content[start:end]))
					}
					// Also check for boundary with CRLF
					crlfBoundaryMarker := []byte("\r\n--" + boundary)
					if bytes.Contains(content, crlfBoundaryMarker) {
						c.logger.Debug("found boundary with CRLF",
							"message_id", popMsg.ID,
							"boundary", boundary)
					}

					attachments, err = c.extractAttachmentsMultipart(content, boundary)
					if err != nil {
						c.logger.Debug("failed to extract attachments with multipart parser",
							"error", err,
							"message_id", popMsg.ID,
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
			email, err := parsemail.Parse(bytes.NewReader(content))
			if err != nil {
				c.logger.Debug("failed to parse email", "error", err, "message_id", popMsg.ID)
				result.Status = "error"
				result.ErrorMessage = fmt.Sprintf("failed to parse email: %v", err)
				results = append(results, result)
				continue
			}
			attachments = append(attachments, email.Attachments...)
			for _, ef := range email.EmbeddedFiles {
				attachments = append(attachments, parsemail.Attachment{
					Filename: fmt.Sprintf("embedded_%d%s", time.Now().UnixNano(), getExtensionFromContentType(ef.ContentType)),
					Data:     ef.Data,
				})
			}
		}

		c.logger.Debug("parsed email",
			"attachment_count", len(attachments))

		// Extract subject for tracking
		// We don't have access to the subject directly from popMsg
		// We'll need to extract it from the parsed email or leave it blank
		// For now, we'll leave it blank and just use the message ID for tracking

		// Process attachments
		for _, a := range attachments {
			if c.isAllowedAttachment(a.Filename) {
				content, err := io.ReadAll(a.Data)
				if err != nil {
					c.logger.Error("failed to read attachment data",
						"filename", a.Filename,
						"error", err,
					)
					continue
				}
				if err := c.saveAttachment(a.Filename, content); err != nil {
					c.logger.Error("failed to save attachment",
						"filename", a.Filename,
						"error", err,
					)
					continue
				}
				result.Attachments = append(result.Attachments, a.Filename)
			}
		}

		if len(result.Attachments) > 0 {
			result.Status = "completed"
		} else {
			result.Status = "no_attachments"
		}

		results = append(results, result)

		// Track this email as downloaded with the unique ID
		if trackingManager != nil {
			if err := trackingManager.TrackEmail(
				req.Config.Protocol,
				req.Config.Server,
				req.Config.Username,
				uniqueID, // Use the unique ID
				result.Subject,
				result.Status,
			); err != nil {
				c.logger.Warn("failed to track email",
					"message_id", uniqueID,
					"error", err)
				// Continue processing
			}
		}

		// Delete message if configured
		if req.Config.DeleteAfterDownload {
			if err := conn.Dele(popMsg.ID); err != nil {
				c.logger.Error("failed to delete message",
					"message_id", popMsg.ID,
					"error", err,
				)
			}
		}
	}

	return results, nil
}

func (c *POP3Client) isAllowedAttachment(filename string) bool {
	if filename == "" {
		c.logger.Debug("empty filename", "filename", filename)
		return false
	}

	ext := filepath.Ext(filename)
	if ext == "" {
		c.logger.Debug("no extension", "filename", filename)
		return false
	}

	ext = strings.ToLower(ext)
	c.logger.Debug("checking attachment",
		"filename", filename,
		"extension", ext,
		"allowed_types", c.cfg.Email.Attachments.AllowedTypes)

	for _, allowedType := range c.cfg.Email.Attachments.AllowedTypes {
		allowedType = strings.ToLower(allowedType)
		// Compare with and without dot
		if ext == allowedType ||
			ext == "."+strings.TrimPrefix(allowedType, ".") ||
			strings.TrimPrefix(ext, ".") == strings.TrimPrefix(allowedType, ".") {
			c.logger.Debug("allowed attachment", "filename", filename, "extension", ext)
			return true
		}
	}

	c.logger.Debug("attachment not allowed", "filename", filename, "extension", ext)
	return false
}

func (c *POP3Client) saveAttachment(filename string, content []byte) error {
	// Validate content size
	if int64(len(content)) > c.cfg.Email.Attachments.MaxSize {
		return fmt.Errorf("attachment size %d exceeds maximum allowed size %d", len(content), c.cfg.Email.Attachments.MaxSize)
	}

	// First sanitize if configured (before pattern application)
	if c.cfg.Email.Attachments.SanitizeFilenames {
		filename = c.sanitizeFilename(filename)
	}

	// Apply the naming pattern
	filename = c.generateFilename(filename, time.Now().UTC())

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
		if mimeExt, ok := mimeToExt[contentType]; ok {
			filename = filename + mimeExt
			ext = mimeExt
		}
	}

	// Sanitize filename if configured
	if c.cfg.Email.Attachments.SanitizeFilenames {
		filename = c.sanitizeFilename(filename)
	}

	if err := os.MkdirAll(c.cfg.Email.Attachments.StoragePath, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	var finalPath string
	if c.cfg.Email.Attachments.PreserveStructure {
		// Create date-based subdirectories
		dateDir := time.Now().UTC().Format("2006/01/02")
		fullDir := filepath.Join(c.cfg.Email.Attachments.StoragePath, dateDir)
		if err := os.MkdirAll(fullDir, 0755); err != nil {
			return fmt.Errorf("failed to create date directory: %w", err)
		}
		finalPath = filepath.Join(fullDir, filename)
	} else {
		finalPath = filepath.Join(c.cfg.Email.Attachments.StoragePath, filename)
	}
	c.logger.Debug("final path", "path", finalPath)

	// Check if file already exists
	if _, err := os.Stat(finalPath); err == nil {
		// File exists, append timestamp to filename
		ext := filepath.Ext(finalPath)
		base := strings.TrimSuffix(finalPath, ext)
		// Ensure we have an extension
		if ext == "" {
			ext = filepath.Ext(filename)
		}
		finalPath = fmt.Sprintf("%s_%d%s", base, time.Now().UnixNano(), ext)
	}

	// Create file with restricted permissions
	f, err := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	// Write content
	if _, err := f.Write(content); err != nil {
		os.Remove(finalPath) // Clean up on error
		return fmt.Errorf("failed to write file content: %w", err)
	}

	return nil
}

func (c *POP3Client) sanitizeFilename(filename string) string {
	// Remove any path components
	filename = filepath.Base(filename)

	// Replace potentially problematic characters
	replacer := strings.NewReplacer(
		" ", "_",
		"&", "_and_",
		"#", "_hash_",
		"{", "_",
		"}", "_",
		"\\", "_",
		"<", "_",
		">", "_",
		"*", "_",
		"?", "_",
		"!", "_",
		"$", "_",
		"'", "_",
		"\"", "_",
		":", "_",
		"@", "_at_",
		"+", "_plus_",
		"`", "_",
		"|", "_",
		"=", "_equals_",
	)

	sanitized := replacer.Replace(filename)

	// Ensure the filename isn't too long
	if len(sanitized) > 255 {
		ext := filepath.Ext(sanitized)
		sanitized = sanitized[:255-len(ext)] + ext
	}

	return sanitized
}

func (c *POP3Client) generateFilename(originalName string, downloadTime time.Time) string {
	pattern := c.cfg.Email.Attachments.NamingPattern

	// Add detailed config logging
	c.logger.Debug("checking naming pattern config",
		"raw_pattern", pattern,
		"config_attachments", c.cfg.Email.Attachments)

	if pattern == "" {
		// Use default pattern if none specified
		pattern = "${unixtime}_${filename}"
		c.logger.Debug("using default pattern", "pattern", pattern)
	}

	// Split filename into base and extension
	ext := filepath.Ext(originalName)
	baseFilename := strings.TrimSuffix(originalName, ext)

	// Create the timestamp part using nanoseconds
	timestamp := fmt.Sprintf("%d", downloadTime.UnixNano())

	// Replace pattern variables
	result := pattern
	result = strings.ReplaceAll(result, "${unixtime}", timestamp)
	result = strings.ReplaceAll(result, "${filename}", baseFilename)

	// Log the filename generation process
	c.logger.Debug("generating filename",
		"original", originalName,
		"pattern", pattern,
		"timestamp", timestamp,
		"baseFilename", baseFilename,
		"result", result+ext)

	// Ensure the extension is preserved
	return result + ext
}

func (c *POP3Client) checkResponse(response string, context string) error {
	if strings.HasPrefix(response, "-ERR") {
		c.logger.Error("server error",
			"context", context,
			"response", response,
		)
		return fmt.Errorf("%s failed: %s", context, response)
	}
	return nil
}

func (c *POP3Client) extractAttachments(msgBody io.Reader) ([]parsemail.Attachment, error) {
	email, err := parsemail.Parse(msgBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	var attachments []parsemail.Attachment
	attachments = append(attachments, email.Attachments...)
	// Convert EmbeddedFiles to Attachments
	for _, ef := range email.EmbeddedFiles {
		attachments = append(attachments, parsemail.Attachment{
			Filename: fmt.Sprintf("embedded_%d%s", time.Now().UnixNano(), getExtensionFromContentType(ef.ContentType)),
			Data:     ef.Data,
		})
	}

	c.logger.Debug("found attachments",
		"regular_count", len(email.Attachments),
		"embedded_count", len(email.EmbeddedFiles),
		"total_count", len(attachments))

	return attachments, nil
}

func getExtensionFromContentType(contentType string) string {
	if ext, ok := mimeToExt[contentType]; ok {
		return ext
	}
	// Default to .bin if content type is unknown
	return ".bin"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func processHTML(htmlContent []byte) []parsemail.Attachment {
	var attachments []parsemail.Attachment
	// Process base64 encoded images in HTML content
	for _, line := range bytes.Split(htmlContent, []byte("\n")) {
		if bytes.Contains(line, []byte("data:image/")) && bytes.Contains(line, []byte(";base64,")) {
			parts := bytes.Split(line, []byte(";base64,"))
			if len(parts) == 2 {
				contentType := string(bytes.TrimPrefix(parts[0], []byte("data:")))
				decoded, err := base64.StdEncoding.DecodeString(string(parts[1]))
				if err == nil {
					ext := ".bin"
					if mimeExt, ok := mimeToExt[contentType]; ok {
						ext = mimeExt
					}
					attachments = append(attachments, parsemail.Attachment{
						Filename: fmt.Sprintf("embedded_image_%d%s", time.Now().UnixNano(), ext),
						Data:     bytes.NewReader(decoded),
					})
				}
			}
		}
	}
	return attachments
}
