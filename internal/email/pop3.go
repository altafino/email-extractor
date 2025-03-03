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

// DownloadEmails downloads emails from POP3 server with improved error handling and performance
func (c *POP3Client) DownloadEmails(ctx context.Context, req models.EmailDownloadRequest) ([]models.DownloadResult, error) {
	c.logger.Info("starting email download",
		"server", req.Config.Server,
		"username", req.Config.Username)

	// Initialize managers
	trackingManager, errorLogger := c.initializeManagers()
	defer c.closeManagers(trackingManager, errorLogger)

	// Connect to POP3 server
	conn, err := c.Connect(req.Config)
	if err != nil {
		c.logConnectionError(err, errorLogger, req.Config)
		return nil, err
	}
	defer conn.Quit()

	// Get mailbox statistics
	count, size, err := c.getMailboxStats(conn, errorLogger, req.Config)
	if err != nil {
		return nil, err
	}
	c.logger.Info("mailbox stats", "messages", count, "total_size", size)

	// Get list of all messages
	msgList, err := c.getMessageList(conn, errorLogger, req.Config)
	if err != nil {
		return nil, err
	}

	// Initialize date filtering
	dateFilter := c.initializeDateFilter()

	// Process messages
	results := make([]models.DownloadResult, 0, len(msgList))
	for _, popMsg := range msgList {
		// Check for context cancellation
		if ctx.Err() != nil {
			c.logger.Warn("context cancelled, stopping email download", "error", ctx.Err())
			break
		}

		// Process individual message
		result, processed := c.processMessage(ctx, conn, popMsg, trackingManager, errorLogger, dateFilter, req.Config)
		if processed {
			results = append(results, result)
		}
	}

	c.logger.Info("completed email download",
		"server", req.Config.Server,
		"username", req.Config.Username,
		"processed_messages", len(results))

	return results, nil
}

// Helper functions

// initializeManagers sets up tracking and error logging managers
func (c *POP3Client) initializeManagers() (*tracking.Manager, *errorlog.Manager) {
	var trackingManager *tracking.Manager
	var errorLogger *errorlog.Manager
	var err error

	// Create tracking manager
	if c.cfg.Email.Tracking.Enabled {
		trackingManager, err = tracking.NewManager(c.cfg, c.logger)
		if err != nil {
			c.logger.Error("failed to initialize tracking manager", "error", err)
			// Continue without tracking if it fails
		}
	}

	// Create error logging manager
	if c.cfg.Email.ErrorLogging.Enabled {
		c.logger.Debug("initializing error logger",
			"enabled", c.cfg.Email.ErrorLogging.Enabled,
			"storage_path", c.cfg.Email.ErrorLogging.StoragePath)

		errorLogger, err = errorlog.NewManager(c.cfg, c.logger)
		if err != nil {
			c.logger.Error("failed to initialize error logger",
				"error", err,
				"config", c.cfg.Email.ErrorLogging)
			// Continue without error logging if it fails
		}
	}

	return trackingManager, errorLogger
}

// closeManagers safely closes tracking and error logging managers
func (c *POP3Client) closeManagers(trackingManager *tracking.Manager, errorLogger *errorlog.Manager) {
	if trackingManager != nil {
		trackingManager.Close()
	}
	if errorLogger != nil {
		errorLogger.Close()
	}
}

// logConnectionError logs POP3 connection errors
func (c *POP3Client) logConnectionError(err error, errorLogger *errorlog.Manager, config models.EmailConfig) {
	c.logger.Error("failed to connect to POP3 server", "error", err)
	
	if errorLogger != nil {
		errorLogger.LogError(errorlog.EmailError{
			Protocol:  config.Protocol,
			Server:    config.Server,
			Username:  config.Username,
			ErrorTime: time.Now().UTC(),
			ErrorType: "connection",
			ErrorMsg:  fmt.Sprintf("failed to connect: %v", err),
		})
	}
}

// getMailboxStats retrieves mailbox statistics
func (c *POP3Client) getMailboxStats(conn *pop3.Conn, errorLogger *errorlog.Manager, config models.EmailConfig) (int, int, error) {
	count, size, err := conn.Stat()
	if err != nil {
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  config.Protocol,
				Server:    config.Server,
				Username:  config.Username,
				ErrorTime: time.Now().UTC(),
				ErrorType: "mailbox_stats",
				ErrorMsg:  fmt.Sprintf("failed to get mailbox stats: %v", err),
			})
		}
		return 0, 0, fmt.Errorf("failed to get mailbox stats: %w", err)
	}
	return count, size, nil
}

// getMessageList retrieves the list of messages
func (c *POP3Client) getMessageList(conn *pop3.Conn, errorLogger *errorlog.Manager, config models.EmailConfig) ([]*pop3.MessageInfo, error) {
	msgList, err := conn.List(0)
	if err != nil {
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  config.Protocol,
				Server:    config.Server,
				Username:  config.Username,
				ErrorTime: time.Now().UTC(),
				ErrorType: "list_messages",
				ErrorMsg:  fmt.Sprintf("failed to list messages: %v", err),
			})
		}
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}
	return msgList, nil
}

// DateFilter holds date filtering configuration and parsed dates
type DateFilter struct {
	Enabled   bool
	FromTime  time.Time
	ToTime    time.Time
	FromError error
	ToError   error
}

// initializeDateFilter sets up date filtering
func (c *POP3Client) initializeDateFilter() DateFilter {
	filter := DateFilter{
		Enabled: c.cfg.Email.Protocols.POP3.DateFilter.Enabled,
	}

	if !filter.Enabled {
		return filter
	}

	c.logger.Info("date filtering is enabled",
		"from", c.cfg.Email.Protocols.POP3.DateFilter.From,
		"to", c.cfg.Email.Protocols.POP3.DateFilter.To)

	if c.cfg.Email.Protocols.POP3.DateFilter.From != "" {
		filter.FromTime, filter.FromError = time.Parse(time.RFC3339, c.cfg.Email.Protocols.POP3.DateFilter.From)
		if filter.FromError != nil {
			c.logger.Warn("invalid date format for 'from' filter",
				"from", c.cfg.Email.Protocols.POP3.DateFilter.From,
				"error", filter.FromError)
		}
	}

	if c.cfg.Email.Protocols.POP3.DateFilter.To != "" {
		filter.ToTime, filter.ToError = time.Parse(time.RFC3339, c.cfg.Email.Protocols.POP3.DateFilter.To)
		if filter.ToError != nil {
			c.logger.Warn("invalid date format for 'to' filter",
				"to", c.cfg.Email.Protocols.POP3.DateFilter.To,
				"error", filter.ToError)
		}
	}

	return filter
}

// processMessage handles a single POP3 message
func (c *POP3Client) processMessage(ctx context.Context, conn *pop3.Conn, popMsg *pop3.MessageInfo, 
	trackingManager *tracking.Manager, errorLogger *errorlog.Manager, 
	dateFilter DateFilter, config models.EmailConfig) (models.DownloadResult, bool) {
	
	// Initialize result
	result := models.DownloadResult{
		MessageID:    fmt.Sprintf("%d", popMsg.ID),
		DownloadedAt: time.Now().UTC(),
		Status:       "processing",
	}

	// Check if already downloaded by message ID
	if c.isMessageAlreadyDownloaded(trackingManager, popMsg.ID, config) {
		return result, false
	}

	// Apply date filtering if enabled
	if dateFilter.Enabled && (dateFilter.FromError == nil || dateFilter.ToError == nil) {
		// Get the email date from headers
		emailDate, err := c.getEmailDate(conn, popMsg.ID)
		if err == nil && !emailDate.IsZero() {
			// Check if outside date range
			if c.isMessageOutsideDateRange(emailDate, dateFilter, popMsg.ID) {
				return result, false
			}
		}
	}

	// Retrieve and buffer message
	content, err := c.retrieveAndBufferMessage(conn, popMsg.ID, errorLogger, config, result)
	if err != nil {
		return result, true // Return error result
	}

	// Extract email metadata
	sender, subject, sentAt, headers, err := c.extractEmailMetadata(content)
	if err != nil {
		c.logger.Warn("failed to extract email metadata", "error", err)
		// Continue with default values
	}
	
	// Update result with subject
	if subject != "" {
		result.Subject = subject
	}

	// Generate unique message ID
	uniqueID := parser.GenerateUniqueMessageID(content)

	// Check if already downloaded by unique ID
	if c.isUniqueIDAlreadyDownloaded(trackingManager, uniqueID, config) {
		return result, false
	}

	// Process email content to extract attachments
	processedContent, attachments, err := c.processEmailContent(content, popMsg.ID, errorLogger, config, sender, subject, sentAt, uniqueID, result)
	if err != nil {
		return result, true // Return error result
	}

	// Process attachments
	result = c.processAttachments(ctx, attachments, errorLogger, config, sender, subject, sentAt, uniqueID, result)

	// Mark email as downloaded
	c.markEmailAsDownloaded(trackingManager, config, uniqueID, sender, subject, sentAt, len(result.Attachments))

	// Delete message if configured
	c.deleteMessageIfConfigured(conn, popMsg.ID)

	return result, true
}

// Additional helper methods would be implemented here...

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
	return parser.ExtractDateValue(headers, c.logger), nil
}


