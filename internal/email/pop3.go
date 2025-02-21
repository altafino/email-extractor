package email

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/models"
	"github.com/altafino/email-extractor/internal/types"
)

type POP3Client struct {
	cfg      *types.Config
	logger   *slog.Logger
	conn     net.Conn
	text     *textproto.Conn
	host     string
	port     int
	username string
	password string
}

func NewPOP3Client(cfg *types.Config, logger *slog.Logger) *POP3Client {
	return &POP3Client{
		cfg:    cfg,
		logger: logger,
	}
}

func (c *POP3Client) Connect(emailCfg models.EmailConfig) error {
	c.host = emailCfg.Server
	c.port = emailCfg.Port
	c.username = emailCfg.Username
	c.password = emailCfg.Password

	addr := fmt.Sprintf("%s:%d", c.host, c.port)

	var err error
	if emailCfg.EnableTLS {
		c.conn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName:         c.host,
			InsecureSkipVerify: !c.cfg.Email.Security.TLS.VerifyCert,
		})
	} else {
		c.conn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.text = textproto.NewConn(c.conn)

	// Read greeting
	_, err = c.text.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read greeting: %w", err)
	}

	// Send USER command
	if err := c.text.PrintfLine("USER %s", c.username); err != nil {
		return fmt.Errorf("failed to send USER command: %w", err)
	}
	if _, err = c.text.ReadLine(); err != nil {
		return fmt.Errorf("failed to read USER response: %w", err)
	}

	// Send PASS command
	if err := c.text.PrintfLine("PASS %s", c.password); err != nil {
		return fmt.Errorf("failed to send PASS command: %w", err)
	}
	if _, err = c.text.ReadLine(); err != nil {
		return fmt.Errorf("failed to read PASS response: %w", err)
	}

	return nil
}

func (c *POP3Client) Quit() error {
	if c.text != nil {
		if err := c.text.PrintfLine("QUIT"); err != nil {
			return fmt.Errorf("failed to send QUIT command: %w", err)
		}
		c.text.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

func (c *POP3Client) DownloadEmails(req models.EmailDownloadRequest) ([]models.DownloadResult, error) {
	if err := c.Connect(req.Config); err != nil {
		return nil, err
	}
	defer c.Quit()

	// Get message count
	if err := c.text.PrintfLine("STAT"); err != nil {
		return nil, fmt.Errorf("failed to send STAT command: %w", err)
	}
	line, err := c.text.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read STAT response: %w", err)
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid STAT response: %s", line)
	}

	count, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid message count: %w", err)
	}

	var results []models.DownloadResult

	for i := 1; i <= count; i++ {
		result := models.DownloadResult{
			MessageID:    fmt.Sprintf("%d", i),
			DownloadedAt: time.Now().UTC(),
			Status:       "processing",
		}

		// Get message
		if err := c.text.PrintfLine("RETR %d", i); err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to send RETR command: %v", err)
			results = append(results, result)
			continue
		}

		// Read message content
		msgReader := c.text.DotReader()
		msg, err := c.parseEmail(msgReader)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to parse message: %v", err)
			results = append(results, result)
			continue
		}

		result.Subject = msg.subject
		result.Attachments = msg.attachments

		if len(result.Attachments) > 0 {
			result.Status = "completed"
		} else {
			result.Status = "no_attachments"
		}

		results = append(results, result)

		// Delete message if configured
		if req.Config.DeleteAfterDownload {
			if err := c.text.PrintfLine("DELE %d", i); err != nil {
				c.logger.Error("failed to delete message",
					"message_id", i,
					"error", err,
				)
			}
		}
	}

	return results, nil
}

type emailMessage struct {
	subject     string
	attachments []string
}

func (c *POP3Client) parseEmail(r io.Reader) (*emailMessage, error) {
	msg := &emailMessage{}
	reader := bufio.NewReader(r)

	// Read headers
	inHeader := true
	var boundary string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		line = strings.TrimSpace(line)

		if inHeader {
			if line == "" {
				inHeader = false
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "subject:") {
				msg.subject = strings.TrimPrefix(line, "Subject:")
				msg.subject = strings.TrimSpace(msg.subject)
			}
			if strings.HasPrefix(strings.ToLower(line), "content-type:") {
				if idx := strings.Index(line, "boundary="); idx != -1 {
					boundary = strings.Trim(line[idx+9:], `"'`)
				}
			}
		} else {
			if boundary != "" && strings.HasPrefix(line, "--"+boundary) {
				attachment, err := c.parseAttachment(reader)
				if err != nil {
					c.logger.Error("failed to parse attachment", "error", err)
					continue
				}
				if attachment != "" {
					msg.attachments = append(msg.attachments, attachment)
				}
			}
		}
	}

	return msg, nil
}

func (c *POP3Client) parseAttachment(reader *bufio.Reader) (string, error) {
	var filename string
	var content []byte
	inHeader := true

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)

		if inHeader {
			if line == "" {
				inHeader = false
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "content-disposition:") {
				if idx := strings.Index(strings.ToLower(line), "filename="); idx != -1 {
					filename = strings.Trim(line[idx+9:], `"'`)
					if !c.isAllowedAttachment(filename) {
						return "", nil
					}
				}
			}
		} else {
			if line == "" {
				break
			}
			content = append(content, []byte(line)...)
		}
	}

	if filename != "" && len(content) > 0 {
		if err := c.saveAttachment(filename, content); err != nil {
			return "", err
		}
		return filename, nil
	}

	return "", nil
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
