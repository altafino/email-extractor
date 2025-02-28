package email

import (
	"context"
	"crypto/tls"

	"fmt"

	"io"
	"log/slog"

	"path/filepath"

	"time"

	"github.com/altafino/email-extractor/internal/email/parser"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// IMAPClient handles IMAP email operations
type IMAPClient struct {
	config     *types.Config
	client     *client.Client
	logger     *slog.Logger
	attachment *AttachmentHandler
}

// NewIMAPClient creates a new IMAP client
func NewIMAPClient(config *types.Config, logger *slog.Logger) (*IMAPClient, error) {
	return &IMAPClient{
		config:     config,
		logger:     logger,
		attachment: NewAttachmentHandler(config, logger),
	}, nil
}

// Connect establishes a connection to the IMAP server
func (c *IMAPClient) Connect(ctx context.Context) error {
	server := fmt.Sprintf("%s:%d", c.config.Email.Protocols.IMAP.Server, c.config.Email.Protocols.IMAP.DefaultPort)

	c.logger.Info("connecting to IMAP server",
		"server", c.config.Email.Protocols.IMAP.Server,
		"port", c.config.Email.Protocols.IMAP.DefaultPort,
		"tls_enabled", c.config.Email.Protocols.IMAP.Security.TLS.Enabled,
		"username", c.config.Email.Protocols.IMAP.Username,
	)

	var err error

	// For port 143, always use plain connection first, then STARTTLS
	if c.config.Email.Protocols.IMAP.DefaultPort == 143 {
		c.logger.Debug("using port 143, starting with plain connection")
		c.client, err = client.Dial(server)
		if err != nil {
			return fmt.Errorf("failed to connect to IMAP server: %w", err)
		}

		// If TLS is enabled, use STARTTLS to upgrade the connection
		if c.config.Email.Protocols.IMAP.Security.TLS.Enabled {
			c.logger.Debug("upgrading connection with STARTTLS")
			tlsConfig := &tls.Config{
				ServerName:         c.config.Email.Protocols.IMAP.Server,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: !c.config.Email.Protocols.IMAP.Security.TLS.VerifyCert,
			}

			if err := c.client.StartTLS(tlsConfig); err != nil {
				c.logger.Warn("STARTTLS failed, continuing with plain connection", "error", err)
				// Continue with plain connection if STARTTLS fails
			}
		}
	} else if c.config.Email.Protocols.IMAP.Security.TLS.Enabled {
		// For other ports with TLS enabled (like 993), use direct TLS
		c.logger.Debug("using direct TLS connection")
		tlsConfig := &tls.Config{
			ServerName:         c.config.Email.Protocols.IMAP.Server,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !c.config.Email.Protocols.IMAP.Security.TLS.VerifyCert,
		}

		c.client, err = client.DialTLS(server, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to IMAP server: %w", err)
		}
	} else {
		// For other ports without TLS, use plain connection
		c.logger.Debug("using plain connection")
		c.client, err = client.Dial(server)
		if err != nil {
			return fmt.Errorf("failed to connect to IMAP server: %w", err)
		}
	}

	// Set client timeout
	c.client.Timeout = time.Duration(c.config.Email.DefaultTimeout) * time.Second

	// Login
	if err := c.client.Login(c.config.Email.Protocols.IMAP.Username, c.config.Email.Protocols.IMAP.Password); err != nil {
		return fmt.Errorf("IMAP login failed: %w", err)
	}

	c.logger.Info("successfully connected to IMAP server and logged in")
	return nil
}

// FetchMessages retrieves messages from the IMAP server
func (c *IMAPClient) FetchMessages(ctx context.Context) error {
	// Select INBOX
	mbox, err := c.client.Select("INBOX", false)
	if err != nil {
		return fmt.Errorf("failed to select INBOX: %w", err)
	}

	// Get the last N messages
	from := uint32(1)
	to := mbox.Messages
	if mbox.Messages > uint32(c.config.Email.Protocols.IMAP.BatchSize) {
		from = mbox.Messages - uint32(c.config.Email.Protocols.IMAP.BatchSize)
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddRange(from, to)

	// Get message envelope and body structure
	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- c.client.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope, imap.FetchBodyStructure}, messages)
	}()

	for msg := range messages {
		if err := c.processMessage(ctx, msg); err != nil {
			c.logger.Error("Failed to process message", "error", err, "uid", msg.Uid)
		}
	}

	return <-done
}

// processMessage handles individual message processing
func (c *IMAPClient) processMessage(ctx context.Context, msg *imap.Message) error {
	c.logger.Info("processing message", "uid", msg.Uid)

	// Create a new fetch request for the message body
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(msg.SeqNum)

	// Items to fetch - we need the entire message
	items := []imap.FetchItem{imap.FetchRFC822}

	// Channel to receive the message
	messageData := make(chan *imap.Message, 1)
	done := make(chan error, 1)

	// Fetch the message body
	go func() {
		done <- c.client.Fetch(seqSet, items, messageData)
	}()

	// Get the message from the channel
	fetchedMsg := <-messageData
	if err := <-done; err != nil {
		return fmt.Errorf("failed to fetch message body: %w", err)
	}

	if fetchedMsg == nil {
		return fmt.Errorf("no message data received")
	}

	// Get the message body
	var body []byte
	for _, literal := range fetchedMsg.Body {
		b, err := io.ReadAll(literal)
		if err != nil {
			return fmt.Errorf("failed to read message body: %w", err)
		}
		body = b
		break // We only need one body part
	}

	if len(body) == 0 {
		return fmt.Errorf("empty message body")
	}

	// Process email content to extract attachments
	messageID := fmt.Sprintf("%d", msg.Uid)

	_, _, attachments, err := parser.ProcessEmailContent(body, messageID, c.logger)
	if err != nil {
		c.logger.Error("failed to process email content",
			"error", err,
			"uid", msg.Uid)
		return err
	}

	c.logger.Debug("parsed email",
		"uid", msg.Uid,
		"attachment_count", len(attachments))

	// Create attachment config
	attachmentConfig := parser.AttachmentConfig{
		StoragePath:       c.config.Email.Attachments.StoragePath,
		MaxSize:           int64(c.config.Email.Attachments.MaxSize),
		AllowedTypes:      c.config.Email.Attachments.AllowedTypes,
		SanitizeFilenames: c.config.Email.Attachments.SanitizeFilenames,
		PreserveStructure: c.config.Email.Attachments.PreserveStructure,
		FilenamePattern:   c.config.Email.Attachments.NamingPattern,
	}

	// Process attachments
	var savedAttachments []string
	for _, a := range attachments {
		if parser.IsAllowedAttachment(a.Filename, c.config.Email.Attachments.AllowedTypes, c.logger) {
			content, err := io.ReadAll(a.Data)
			if err != nil {
				c.logger.Error("failed to read attachment data",
					"filename", a.Filename,
					"error", err,
				)
				continue
			}

			finalPath, err := parser.SaveAttachment(a.Filename, content, attachmentConfig, c.logger)
			if err != nil {
				c.logger.Error("failed to save attachment",
					"filename", a.Filename,
					"error", err,
				)
				continue
			}

			savedAttachments = append(savedAttachments, filepath.Base(finalPath))
			c.logger.Info("saved attachment",
				"uid", msg.Uid,
				"filename", a.Filename,
				"path", finalPath)
		}
	}

	c.logger.Info("processed message",
		"uid", msg.Uid,
		"saved_attachments", len(savedAttachments))

	return nil
}

// Close terminates the IMAP connection
func (c *IMAPClient) Close() error {
	if c.client != nil {
		c.client.Logout()
		return c.client.Close()
	}
	return nil
}
