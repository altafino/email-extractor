package email

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/email/attachment"
	"github.com/emersion/go-message"

	"github.com/DusanKasan/parsemail"
	"github.com/altafino/email-extractor/internal/email/parser"
	"github.com/altafino/email-extractor/internal/errorlog"
	"github.com/altafino/email-extractor/internal/models"
	"github.com/altafino/email-extractor/internal/tracking"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/jhillyerd/enmime/mediatype"
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
	"text/plain":                    ".txt",
	"text/csv":                      ".csv",
	"application/zip":               ".zip",
	"application/x-zip-compressed":  ".zip",
	"application/x-rar-compressed":  ".rar",
	"application/x-7z-compressed":   ".7z",
	"application/rtf":               ".rtf",
	"application/octet-stream":      ".bin",
	"application/x-compressed":      ".tar",
	"application/x-gzip":            ".gz",
	"application/x-bzip2":           ".bz2",
	"application/x-tar":             ".tar",
	"application/x-7zip-compressed": ".7z",
	"application/x-compressed-tar":  ".tar.gz",
	"application/x-compressed-zip":  ".zip.gz",
	"application/x-compressed-bz2":  ".bz2.gz",
	"application/x-compressed-7z":   ".7z.gz",
	"application/x-compressed-rar":  ".rar.gz",
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
			mediaType, params, invalidParams, err := mediatype.Parse(contentType)
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
						if err != nil {
							c.logger.Error("failed to parse content disposition", "error", err)
						}
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

// Add this function to retrieve and parse email headers to get the date
func (c *POP3Client) getEmailDate(conn *pop3.Conn, msgID int) (time.Time, error) {
	// Use TOP command to retrieve only the headers (0 lines of body)
	msgReader, err := conn.Top(msgID, 0)
	if err != nil {
		c.logger.Error("failed to retrieve message headers", "error", err)
		return time.Time{}, fmt.Errorf("failed to retrieve message headers: %w", err)
	}

	// Read the headers
	headerBytes, err := io.ReadAll(msgReader.Body)
	if err != nil {
		c.logger.Error("failed to read message headers", "error", err)
		return time.Time{}, fmt.Errorf("failed to read message headers: %w", err)
	}

	// Parse the headers
	headers, err := parser.ParseHeaders(bytes.NewReader(headerBytes))
	if err != nil {
		c.logger.Error("failed to parse message headers", "error", err)
		return time.Time{}, fmt.Errorf("failed to parse message headers: %w", err)
	}

	// Extract the date
	date, err := parser.ExtractDateValue(headers, c.logger)
	if err != nil {
		c.logger.Error("failed to extract date from message headers", "error", err)
		return time.Time{}, fmt.Errorf("failed to extract date from message headers: %w", err)
	}
	return date, nil
}

// Modify the DownloadEmails function to apply date filtering
func (c *POP3Client) DownloadEmails(ctx context.Context, req models.EmailDownloadRequest) ([]models.DownloadResult, error) {
	c.logger.Info("starting email download")

	// Create tracking manager
	trackingManager, err := tracking.NewManager(c.cfg, c.logger)
	if err != nil {
		c.logger.Error("failed to initialize tracking manager", "error", err)
		// Continue without tracking if it fails
	} else {
		defer trackingManager.Close()
	}

	// Create error logging manager
	c.logger.Debug("initializing error logger",
		"enabled", c.cfg.Email.ErrorLogging.Enabled,
		"storage_path", c.cfg.Email.ErrorLogging.StoragePath)

	errorLogger, err := errorlog.NewManager(c.cfg, c.logger)
	if err != nil {
		c.logger.Error("failed to initialize error logger",
			"error", err,
			"config", c.cfg.Email.ErrorLogging)
		// Continue without error logging if it fails
	} else {
		defer errorLogger.Close()
	}

	conn, err := c.Connect(req.Config)
	if err != nil {
		// Log connection error
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  req.Config.Protocol,
				Server:    req.Config.Server,
				Username:  req.Config.Username,
				ErrorTime: time.Now().UTC(),
				ErrorType: "connection",
				ErrorMsg:  fmt.Sprintf("failed to connect: %v", err),
			})
		}
		return nil, err
	}
	defer conn.Quit()

	// Get message count
	count, size, err := conn.Stat()
	if err != nil {
		// Log stat error
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  req.Config.Protocol,
				Server:    req.Config.Server,
				Username:  req.Config.Username,
				ErrorTime: time.Now().UTC(),
				ErrorType: "mailbox_stats",
				ErrorMsg:  fmt.Sprintf("failed to get mailbox stats: %v", err),
			})
		}
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
		// Log list error
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  req.Config.Protocol,
				Server:    req.Config.Server,
				Username:  req.Config.Username,
				ErrorTime: time.Now().UTC(),
				ErrorType: "list_messages",
				ErrorMsg:  fmt.Sprintf("failed to list messages: %v", err),
			})
		}
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}

	// Check if date filtering is enabled
	dateFilterEnabled := c.cfg.Email.Protocols.POP3.DateFilter.Enabled

	// Parse date strings to time.Time
	var fromTime, toTime time.Time
	var fromTimeErr, toTimeErr error = nil, nil

	if dateFilterEnabled {
		c.logger.Info("date filtering is enabled",
			"from", c.cfg.Email.Protocols.POP3.DateFilter.From,
			"to", c.cfg.Email.Protocols.POP3.DateFilter.To)

		if c.cfg.Email.Protocols.POP3.DateFilter.From != "" {
			fromTime, fromTimeErr = time.Parse(time.RFC3339, c.cfg.Email.Protocols.POP3.DateFilter.From)
			if fromTimeErr != nil {
				c.logger.Warn("invalid date format for 'from' filter, disabling from filter",
					"from", c.cfg.Email.Protocols.POP3.DateFilter.From,
					"error", fromTimeErr)
				os.Exit(1)
			}
		}

		if c.cfg.Email.Protocols.POP3.DateFilter.To != "" {
			toTime, toTimeErr = time.Parse(time.RFC3339, c.cfg.Email.Protocols.POP3.DateFilter.To)
			if toTimeErr != nil {
				c.logger.Warn("invalid date format for 'to' filter, disabling to filter",
					"to", c.cfg.Email.Protocols.POP3.DateFilter.To,
					"error", toTimeErr)
				os.Exit(2)
			}
		}
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

		c.logger.Debug("date filtering configuration", "dateFilterEnabled", dateFilterEnabled, "fromTime", fromTime, "toTime", toTime)
		// Apply date filtering if enabled
		msgReader := &message.Entity{
			Header: message.Header{},
			Body:   io.NopCloser(bytes.NewReader([]byte{})),
		}
		var isDownloadedInDateRangeCheck bool = false
		if dateFilterEnabled && (fromTimeErr == nil || toTimeErr == nil) {
			// Get the email date from headers
			emailDate, err := c.getEmailDate(conn, popMsg.ID)
			if err != nil {
				c.logger.Warn("failed to get email date, skipping date filter",
					"message_id", popMsg.ID,
					"error", err)
				msgReader, err = conn.Retr(popMsg.ID)
				if err != nil {
					c.logger.Warn("failed to get email before date filter",
						"message_id", popMsg.ID,
						"error", err)
					continue
				}
				emailDate, err = parser.ExtractDateValue(msgReader.Header.Map(), c.logger)
				if err != nil {
					c.logger.Warn("failed to get email date, skipping date filter",
						"message_id", popMsg.ID,
						"error", err)
					continue
				} else {
					c.logger.Debug("email date", "message_id", popMsg.ID, "email_date", emailDate)
					// Check if the email is within the date range
					if !emailDate.IsZero() {
						// Convert all times to UTC for consistent comparison
						emailDateUTC := emailDate.UTC()
						fromTimeUTC := fromTime.UTC()
						toTimeUTC := toTime.UTC()


						if fromTimeErr == nil && !fromTimeUTC.IsZero() && emailDateUTC.Before(fromTimeUTC) {
							c.logger.Debug("skipping message outside date range (too old)",
								"message_id", popMsg.ID,
								"email_date", emailDate,
								"filter_from", fromTimeUTC)
							continue
						}

						if toTimeErr == nil && !toTimeUTC.IsZero() && emailDateUTC.After(toTimeUTC) {
							c.logger.Debug("skipping message outside date range (too new)",
								"message_id", popMsg.ID,
								"email_date", emailDate,
								"filter_to", toTimeUTC)
							continue
						}

						c.logger.Debug("message is within date range",
							"message_id", popMsg.ID,
							"email_date", emailDate)
					}
					isDownloadedInDateRangeCheck = true
				}
				// Continue with date filtering disabled for this message
			} else {
				// Check if the email is within the date range
				if !emailDate.IsZero() {
					if fromTimeErr == nil && !fromTime.IsZero() && emailDate.Before(fromTime) {
						c.logger.Debug("skipping message outside date range (too old)",
							"message_id", popMsg.ID,
							"email_date", emailDate,
							"filter_from", fromTime)
						continue
					}

					if toTimeErr == nil && !toTime.IsZero() && emailDate.After(toTime) {
						c.logger.Debug("skipping message outside date range (too new)",
							"message_id", popMsg.ID,
							"email_date", emailDate,
							"filter_to", toTime)
						continue
					}

					c.logger.Debug("message is within date range",
						"message_id", popMsg.ID,
						"email_date", emailDate)
				}
			}
		}

		// Get message if it's not downloaded in date range check
		if !isDownloadedInDateRangeCheck {
			msgReader, err = conn.Retr(popMsg.ID)
		}
		if err != nil {
			c.logger.Debug("failed to retrieve message", "error", err, "message_id", popMsg.ID)
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to retrieve message: %v", err)

			// Log the error
			if errorLogger != nil {
				errorLogger.LogError(errorlog.EmailError{
					Protocol:  req.Config.Protocol,
					Server:    req.Config.Server,
					Username:  req.Config.Username,
					MessageID: fmt.Sprintf("%d", popMsg.ID),
					ErrorTime: time.Now().UTC(),
					ErrorType: "retrieve_message",
					ErrorMsg:  fmt.Sprintf("failed to retrieve message: %v", err),
				})
			}

			results = append(results, result)
			continue
		}

		// Buffer the message body for multiple reads
		buf := bytes.NewBuffer([]byte{})
		_, err = io.Copy(buf, msgReader.Body)

		if err != nil {
			c.logger.Debug("failed to buffer message", "error", err, "message_id", popMsg.ID)
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to buffer message: %v", err)

			// Log the error
			if errorLogger != nil {
				errorLogger.LogError(errorlog.EmailError{
					Protocol:  req.Config.Protocol,
					Server:    req.Config.Server,
					Username:  req.Config.Username,
					MessageID: fmt.Sprintf("%d", popMsg.ID),
					ErrorTime: time.Now().UTC(),
					ErrorType: "buffer_message",
					ErrorMsg:  fmt.Sprintf("failed to buffer message: %v", err),
				})
			}

			results = append(results, result)
			continue
		}

		// Get message content
		content := buf.Bytes()

		// Extract basic email information for error logging
		var sender, subject string
		var sentAt time.Time

		headers, err := parser.ParseHeaders(bytes.NewReader(content))
		if err != nil {
			c.logger.Warn("failed to parse headers", "error", err)
			// Continue with empty headers map
			headers = make(map[string][]string)
		}

		// Try multiple header variations for From field
		sender = parser.ExtractHeaderValue(headers, []string{"From", "FROM", "from", "Sender", "SENDER", "sender"})

		// Try multiple header variations for Subject field
		subject = parser.ExtractHeaderValue(headers, []string{"Subject", "SUBJECT", "subject"})
		if subject != "" {
			result.Subject = subject
		}

		// Try to parse date with multiple formats and header names
		sentAt, err = parser.ExtractDateValue(headers, c.logger)
		if err != nil {
			c.logger.Warn("failed to extract date from message headers", "error", err)
			// Continue with empty date
			sentAt = time.Time{}
		}

		if sender == "" {
			sender = "unknown"
		}
		if subject == "" {
			subject = "No Subject"
		}

		// Generate a unique message ID
		uniqueID := parser.GenerateUniqueMessageID(content)

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

		// Process email content to extract attachments and collect any errors
		// This step parses the email body and finds any file attachments
		// Returns processed content, attachments list, and potential errors
		content, _, attachments, err := parser.ProcessEmailContent(content, fmt.Sprintf("%d", popMsg.ID), c.logger)
		if err != nil {
			// Log debug info about processing failure
			c.logger.Debug("failed to process email content", "error", err, "message_id", popMsg.ID)

			// Update result status to indicate error
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to process email content: %v", err)

			// Log detailed error information if error logging is enabled
			if errorLogger != nil {
				// Create comprehensive error log entry with email metadata
				errorLogger.LogError(errorlog.EmailError{
					Protocol:  req.Config.Protocol,
					Server:    req.Config.Server,
					Username:  req.Config.Username,
					MessageID: fmt.Sprintf("%d", popMsg.ID),
					Sender:    sender,
					Subject:   subject,
					SentAt:    sentAt,
					ErrorTime: time.Now().UTC(),
					ErrorType: "process_email",
					ErrorMsg:  fmt.Sprintf("failed to process email content: %v", err),
					// Include truncated raw message for debugging purposes
					RawMessage: parser.GetRawMessageSample(content, 1000),
				})
			}

			// Add error result to results list and skip to next message
			results = append(results, result)
			continue
		}

		// Create attachment config with account name
		attachmentConfig := attachment.AttachmentConfig{
			StoragePath:       c.cfg.Email.Attachments.StoragePath,
			MaxSize:           int64(c.cfg.Email.Attachments.MaxSize),
			AllowedTypes:      c.cfg.Email.Attachments.AllowedTypes,
			SanitizeFilenames: c.cfg.Email.Attachments.SanitizeFilenames,
			PreserveStructure: c.cfg.Email.Attachments.PreserveStructure,
			FilenamePattern:   c.cfg.Email.Attachments.NamingPattern,
			AccountName:       c.cfg.Meta.ID, // Add the account name from config ID
		}

		// Process attachments
		var attachmentErrors []string
		for _, a := range attachments {
			if attachment.IsAllowedAttachment(a.Filename, c.cfg.Email.Attachments.AllowedTypes, c.logger) {
				content, err := io.ReadAll(a.Data)
				if err != nil {
					errMsg := fmt.Sprintf("failed to read attachment data: %v", err)
					c.logger.Error("failed to read attachment data",
						"filename", a.Filename,
						"error", err,
					)
					attachmentErrors = append(attachmentErrors, errMsg)

					// Log attachment error
					if errorLogger != nil {
						errorLogger.LogError(errorlog.EmailError{
							Protocol:  req.Config.Protocol,
							Server:    req.Config.Server,
							Username:  req.Config.Username,
							MessageID: uniqueID,
							Sender:    sender,
							Subject:   subject,
							SentAt:    sentAt,
							ErrorTime: time.Now().UTC(),
							ErrorType: "attachment_read",
							ErrorMsg:  errMsg,
						})
					}
					continue
				}

				storageConfig := attachment.StorageConfig{
					Type:            attachment.StorageType(c.cfg.Email.Attachments.Storage.Type),
					CredentialsFile: c.cfg.Email.Attachments.Storage.CredentialsFile, // only needed for GDrive
					ParentFolderID:  c.cfg.Email.Attachments.Storage.ParentFolderID,  // only needed for GDrive
				}
				finalPath, err := attachment.SaveAttachment(ctx, a.Filename, content, attachmentConfig, storageConfig, c.logger)
				if err != nil {
					errMsg := fmt.Sprintf("failed to save attachment: %v", err)
					c.logger.Error("failed to save attachment",
						"filename", a.Filename,
						"error", err,
					)
					attachmentErrors = append(attachmentErrors, errMsg)

					// Log attachment error
					if errorLogger != nil {
						errorLogger.LogError(errorlog.EmailError{
							Protocol:  req.Config.Protocol,
							Server:    req.Config.Server,
							Username:  req.Config.Username,
							MessageID: uniqueID,
							Sender:    sender,
							Subject:   subject,
							SentAt:    sentAt,
							ErrorTime: time.Now().UTC(),
							ErrorType: "attachment_save",
							ErrorMsg:  errMsg,
						})
					}
					continue
				}
				result.Attachments = append(result.Attachments, filepath.Base(finalPath))
			}
		}

		if len(result.Attachments) > 0 {
			result.Status = "completed"
		} else {
			// If we had attachment errors but no successful attachments
			if len(attachmentErrors) > 0 {
				result.Status = "error"
				result.ErrorMessage = strings.Join(attachmentErrors, "; ")
			} else {
				result.Status = "no_attachments"
			}
		}

		results = append(results, result)

		// Mark email as downloaded in tracking system
		if trackingManager != nil && c.cfg.Email.Tracking.TrackDownloaded {
			err := trackingManager.MarkEmailDownloaded(
				req.Config.Protocol,
				req.Config.Server,
				req.Config.Username,
				uniqueID,
				sender,
				subject,
				sentAt,
				len(result.Attachments),
			)
			if err != nil {
				c.logger.Warn("failed to mark email as downloaded",
					"message_id", uniqueID,
					"error", err)
			}
		}

		// Delete message if configured
		if c.cfg.Email.Protocols.POP3.DeleteAfterDownload {
			c.logger.Debug("deleting message", "message_id", popMsg.ID)
			if err := conn.Dele(popMsg.ID); err != nil {
				c.logger.Warn("failed to delete message",
					"message_id", popMsg.ID,
					"error", err)
			}
		}
	}

	return results, nil
}
