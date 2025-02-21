package email

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/models"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-pop3"
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

func (c *POP3Client) Connect(emailCfg models.EmailConfig) (*pop3.Client, error) {
	var client *pop3.Client
	var err error

	addr := fmt.Sprintf("%s:%d", emailCfg.Server, emailCfg.Port)

	if emailCfg.EnableTLS {
		client, err = pop3.DialTLS(addr, &tls.Config{
			ServerName:         emailCfg.Server,
			InsecureSkipVerify: !c.cfg.Email.Security.TLS.VerifyCert,
		})
	} else {
		client, err = pop3.Dial(addr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to POP3 server: %w", err)
	}

	if err := client.Auth(emailCfg.Username, emailCfg.Password); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return client, nil
}

func (c *POP3Client) DownloadEmails(req models.EmailDownloadRequest) ([]models.DownloadResult, error) {
	client, err := c.Connect(req.Config)
	if err != nil {
		return nil, err
	}
	defer client.Quit()

	messages, err := client.ListAll()
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}

	var results []models.DownloadResult

	for _, msg := range messages {
		result := models.DownloadResult{
			MessageID:    fmt.Sprintf("%d", msg.ID),
			DownloadedAt: time.Now().UTC(),
			Status:       "processing",
		}

		msgReader, err := client.Retr(msg.ID)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to retrieve message: %v", err)
			results = append(results, result)
			continue
		}

		mr, err := mail.CreateReader(msgReader)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("failed to parse message: %v", err)
			results = append(results, result)
			continue
		}

		header := mr.Header
		if subject, err := header.Subject(); err == nil {
			result.Subject = subject
		}

		// Process attachments
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}

			switch h := p.Header.(type) {
			case *mail.AttachmentHeader:
				filename, _ := h.Filename()
				if c.isAllowedAttachment(filename) {
					if err := c.saveAttachment(p, filename, &result); err != nil {
						c.logger.Error("failed to save attachment",
							"filename", filename,
							"error", err,
						)
					}
				}
			}
		}

		if len(result.Attachments) > 0 {
			result.Status = "completed"
		} else {
			result.Status = "no_attachments"
		}

		results = append(results, result)

		// Delete message if configured
		if req.Config.DeleteAfterDownload {
			if err := client.Dele(msg.ID); err != nil {
				c.logger.Error("failed to delete message",
					"message_id", msg.ID,
					"error", err,
				)
			}
		}
	}

	return results, nil
}

func (c *POP3Client) isAllowedAttachment(filename string) bool {
	if filename == "" {
		return false
	}

	ext := filepath.Ext(filename)
	if ext == "" {
		return false
	}

	// Check if extension is in allowed types
	for _, allowedType := range c.cfg.Email.Attachments.AllowedTypes {
		if strings.EqualFold(ext, allowedType) {
			return true
		}
	}

	return false
}

func (c *POP3Client) saveAttachment(p *mail.Part, filename string, result *models.DownloadResult) error {
	// Implementation of attachment saving
	// TODO: Implement this method
	return nil
}
