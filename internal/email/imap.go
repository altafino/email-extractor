package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/altafino/email-extractor/internal/types"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// IMAPClient handles IMAP email operations
type IMAPClient struct {
	config     *types.Config
	client     *client.Client
	logger     Logger
	attachment *AttachmentHandler
}

// NewIMAPClient creates a new IMAP client
func NewIMAPClient(config *types.Config, logger Logger) (*IMAPClient, error) {
	return &IMAPClient{
		config:     config,
		logger:     logger,
		attachment: NewAttachmentHandler(config, logger),
	}, nil
}

// Connect establishes a connection to the IMAP server
func (c *IMAPClient) Connect(ctx context.Context) error {
	var err error
	server := fmt.Sprintf("%s:%d", c.config.Email.Protocols.IMAP.Server, c.config.Email.Protocols.IMAP.DefaultPort)

	// Set connection timeout
	timeout := time.Duration(c.config.Email.DefaultTimeout) * time.Second

	// Log connection attempt with obfuscated password
	c.logger.Info("connecting to IMAP server",
		"server", c.config.Email.Protocols.IMAP.Server,
		"port", c.config.Email.Protocols.IMAP.DefaultPort,
		"tls_enabled", c.config.Email.Protocols.IMAP.Security.TLS.Enabled,
		"username", c.config.Email.Protocols.IMAP.Username,
		"password", "********", // Obfuscated password
	)

	if c.config.Email.Protocols.IMAP.Security.TLS.Enabled {
		// Configure TLS
		tlsConfig := &tls.Config{
			ServerName:         c.config.Email.Protocols.IMAP.Server,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !c.config.Email.Protocols.IMAP.Security.TLS.VerifyCert,
		}
		c.client, err = client.DialTLS(server, tlsConfig)
	} else {
		c.client, err = client.Dial(server)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to IMAP server: %w", err)
	}

	// Set client timeout
	c.client.Timeout = timeout

	// Login
	if err := c.client.Login(c.config.Email.Protocols.IMAP.Username, c.config.Email.Protocols.IMAP.Password); err != nil {
		return fmt.Errorf("IMAP login failed: %w", err)
	}

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
	// TODO: Implement message processing logic
	// 1. Check for attachments in body structure
	// 2. Download attachments
	// 3. Save using attachment handler
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
