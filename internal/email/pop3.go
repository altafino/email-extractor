package email

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/models"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/knadh/go-pop3"
)

type POP3Client struct {
	cfg    *types.Config
	logger *slog.Logger
}

func NewPOP3Client(cfg *types.Config, logger *slog.Logger) *POP3Client {
	return &POP3Client{
		cfg:    cfg,
		logger: logger,
	}
}

func (c *POP3Client) Connect(emailCfg models.EmailConfig) (*pop3.Conn, error) {

	c.logger.Info("connecting to POP3 server",
		"server", emailCfg.Server,
		"port", emailCfg.Port,
		"tls_enabled", emailCfg.EnableTLS,
		"username", emailCfg.Username,
		"password", emailCfg.Password,
		"tls_skip_verify", !c.cfg.Email.Security.TLS.VerifyCert,
		"tls_config", c.cfg.Email.Security.TLS,
	)

	// Initialize POP3 client
	p := pop3.New(pop3.Opt{
		Host:          emailCfg.Server,
		Port:          emailCfg.Port,
		TLSEnabled:    emailCfg.EnableTLS,
		TLSSkipVerify: !c.cfg.Email.Security.TLS.VerifyCert,
	})

	// Create new connection
	conn, err := p.NewConn()
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Authenticate
	if err := conn.Auth(emailCfg.Username, emailCfg.Password); err != nil {
		conn.Quit()
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	c.logger.Info("successfully connected to POP3 server")
	return conn, nil
}

func (c *POP3Client) DownloadEmails(req models.EmailDownloadRequest) ([]models.DownloadResult, error) {
	c.logger.Info("starting email download")

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
	messages, err := conn.List(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}

	for _, msg := range messages {
		result := models.DownloadResult{
			MessageID:    fmt.Sprintf("%d", msg.ID),
			DownloadedAt: time.Now().UTC(),
			Status:       "processing",
		}

		// Get message
		msgReader, err := conn.Retr(msg.ID)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to retrieve message: %v", err)
			results = append(results, result)
			continue
		}

		// Convert message.Entity to io.Reader
		messageBytes, err := io.ReadAll(msgReader.Body)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to read message body: %v", err)
			results = append(results, result)
			continue
		}

		// Parse the email message
		message, err := mail.ReadMessage(bytes.NewReader(messageBytes))
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to parse message: %v", err)
			results = append(results, result)
			continue
		}

		// Get subject from headers
		result.Subject = message.Header.Get("Subject")

		// Process attachments
		err = c.processAttachments(message, &result)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to process attachments: %v", err)
			results = append(results, result)
			continue
		}

		if len(result.Attachments) > 0 {
			result.Status = "completed"
		} else {
			result.Status = "no_attachments"
		}

		results = append(results, result)

		// Delete message if configured
		if req.Config.DeleteAfterDownload {
			if err := conn.Dele(msg.ID); err != nil {
				c.logger.Error("failed to delete message",
					"message_id", msg.ID,
					"error", err,
				)
			}
		}
	}

	return results, nil
}

func (c *POP3Client) processAttachments(message *mail.Message, result *models.DownloadResult) error {
	// Get the Content-Type header
	contentType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		return fmt.Errorf("failed to parse content type: %w", err)
	}

	// Handle multipart messages
	if strings.HasPrefix(contentType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return fmt.Errorf("no boundary found in multipart message")
		}

		reader := multipart.NewReader(message.Body, boundary)
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				c.logger.Error("failed to read part", "error", err)
				continue
			}

			// Check if this part is an attachment
			filename := part.FileName()
			if filename == "" {
				continue // Not an attachment
			}

			if !c.isAllowedAttachment(filename) {
				c.logger.Debug("skipping disallowed attachment", "filename", filename)
				continue
			}

			// Read attachment content
			content, err := io.ReadAll(part)
			if err != nil {
				c.logger.Error("failed to read attachment content",
					"filename", filename,
					"error", err,
				)
				continue
			}

			// Save attachment
			if err := c.saveAttachment(filename, content); err != nil {
				c.logger.Error("failed to save attachment",
					"filename", filename,
					"error", err,
				)
				continue
			}

			result.Attachments = append(result.Attachments, filename)
		}
	}

	return nil
}

func (c *POP3Client) isAllowedAttachment(filename string) bool {
	if filename == "" {
		return false
	}

	ext := filepath.Ext(filename)
	if ext == "" {
		return false
	}

	for _, allowedType := range c.cfg.Email.Attachments.AllowedTypes {
		if strings.EqualFold(ext, allowedType) {
			return true
		}
	}

	return false
}

func (c *POP3Client) saveAttachment(filename string, content []byte) error {
	// Validate content size
	if int64(len(content)) > c.cfg.Email.Attachments.MaxSize {
		return fmt.Errorf("attachment size %d exceeds maximum allowed size %d", len(content), c.cfg.Email.Attachments.MaxSize)
	}

	// Sanitize filename if configured
	if c.cfg.Email.Attachments.SanitizeFilenames {
		filename = c.sanitizeFilename(filename)
	}

	if err := os.MkdirAll(c.cfg.Email.Attachments.StoragePath, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	filename = c.generateFilename(filename, time.Now().UTC())

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

	// Check if file already exists
	if _, err := os.Stat(finalPath); err == nil {
		// File exists, append timestamp to filename
		ext := filepath.Ext(finalPath)
		base := strings.TrimSuffix(finalPath, ext)
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
	pattern = strings.ReplaceAll(pattern, "${date}", downloadTime.Format("2006-01-02"))
	pattern = strings.ReplaceAll(pattern, "${filename}", originalName)
	return pattern
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
