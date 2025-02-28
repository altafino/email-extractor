package email

import (
	"bytes"
	"context"
	"crypto/tls"

	"fmt"

	"io"
	"log/slog"

	"path/filepath"

	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/email/parser"
	"github.com/altafino/email-extractor/internal/errorlog"
	"github.com/altafino/email-extractor/internal/tracking"
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
	// Create tracking manager
	trackingManager, err := tracking.NewManager(c.config, c.logger)
	if err != nil {
		c.logger.Error("failed to initialize tracking manager", "error", err)
		// Continue without tracking if it fails
	} else {
		defer trackingManager.Close()
	}

	// Create error logging manager
	c.logger.Debug("initializing error logger",
		"enabled", c.config.Email.ErrorLogging.Enabled,
		"storage_path", c.config.Email.ErrorLogging.StoragePath)

	errorLogger, err := errorlog.NewManager(c.config, c.logger)
	if err != nil {
		c.logger.Error("failed to initialize error logger",
			"error", err,
			"config", c.config.Email.ErrorLogging)
		// Continue without error logging if it fails
	} else {
		defer errorLogger.Close()
	}

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
		done <- c.client.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope, imap.FetchBodyStructure, imap.FetchUid}, messages)
	}()

	for msg := range messages {
		// Process each message
		if err := c.processMessage(ctx, msg, trackingManager, errorLogger); err != nil {
			c.logger.Error("Failed to process message", "error", err, "uid", msg.Uid)
		}
	}

	return <-done
}

// processMessage handles individual message processing
func (c *IMAPClient) processMessage(ctx context.Context, msg *imap.Message, trackingManager *tracking.Manager, errorLogger *errorlog.Manager) error {
	c.logger.Info("processing message", "uid", msg.Uid)

	// Check if this message has already been downloaded using the UID
	if trackingManager != nil && c.config.Email.Tracking.TrackDownloaded {
		downloaded, err := trackingManager.IsEmailDownloaded(
			"IMAP",
			c.config.Email.Protocols.IMAP.Server,
			c.config.Email.Protocols.IMAP.Username,
			fmt.Sprintf("%d", msg.Uid),
		)
		if err != nil {
			c.logger.Warn("failed to check if email was downloaded",
				"uid", msg.Uid,
				"error", err)
			// Continue processing this message
		} else if downloaded {
			c.logger.Debug("skipping already downloaded message", "uid", msg.Uid)
			return nil // Skip this message
		}
	}

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
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  "IMAP",
				Server:    c.config.Email.Protocols.IMAP.Server,
				Username:  c.config.Email.Protocols.IMAP.Username,
				MessageID: fmt.Sprintf("%d", msg.Uid),
				ErrorTime: time.Now().UTC(),
				ErrorType: "fetch_message",
				ErrorMsg:  fmt.Sprintf("failed to fetch message body: %v", err),
			})
		}
		return fmt.Errorf("failed to fetch message body: %w", err)
	}

	if fetchedMsg == nil {
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  "IMAP",
				Server:    c.config.Email.Protocols.IMAP.Server,
				Username:  c.config.Email.Protocols.IMAP.Username,
				MessageID: fmt.Sprintf("%d", msg.Uid),
				ErrorTime: time.Now().UTC(),
				ErrorType: "empty_message",
				ErrorMsg:  "no message data received",
			})
		}
		return fmt.Errorf("no message data received")
	}

	// Get the message body
	var body []byte
	for _, literal := range fetchedMsg.Body {
		b, err := io.ReadAll(literal)
		if err != nil {
			if errorLogger != nil {
				errorLogger.LogError(errorlog.EmailError{
					Protocol:  "IMAP",
					Server:    c.config.Email.Protocols.IMAP.Server,
					Username:  c.config.Email.Protocols.IMAP.Username,
					MessageID: fmt.Sprintf("%d", msg.Uid),
					ErrorTime: time.Now().UTC(),
					ErrorType: "read_body",
					ErrorMsg:  fmt.Sprintf("failed to read message body: %v", err),
				})
			}
			return fmt.Errorf("failed to read message body: %w", err)
		}
		body = b
		break // We only need one body part
	}

	if len(body) == 0 {
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  "IMAP",
				Server:    c.config.Email.Protocols.IMAP.Server,
				Username:  c.config.Email.Protocols.IMAP.Username,
				MessageID: fmt.Sprintf("%d", msg.Uid),
				ErrorTime: time.Now().UTC(),
				ErrorType: "empty_body",
				ErrorMsg:  "empty message body",
			})
		}
		return fmt.Errorf("empty message body")
	}

	// Extract basic email information for logging
	var sender, subject string
	var sentAt time.Time

	headers, err := parser.ParseHeaders(bytes.NewReader(body))
	if err != nil {
		c.logger.Warn("failed to parse headers", "error", err)
		// Continue with empty headers map
		headers = make(map[string][]string)
	}

	// Try multiple header variations for From field
	sender = parser.ExtractHeaderValue(headers, []string{"From", "FROM", "from", "Sender", "SENDER", "sender"})
	c.logger.Debug("extracted sender", "sender", sender, "raw_headers", headers)

	// Try multiple header variations for Subject field
	subject = parser.ExtractHeaderValue(headers, []string{"Subject", "SUBJECT", "subject"})
	if subject != "" {
		c.logger.Debug("extracted subject", "subject", subject)
	}

	// Try to parse date with multiple formats and header names
	sentAt = parser.ExtractDateValue(headers, c.logger)

	c.logger.Debug("email info", "sender", sender, "subject", subject, "sent_at", sentAt)
	if sender == "" {
		sender = "unknown"
		c.logger.Debug("using default sender", "sender", sender)
	}
	if subject == "" {
		subject = "No Subject"
		c.logger.Debug("using default subject", "subject", subject)
	}

	// Generate a unique message ID
	uniqueID := parser.GenerateUniqueMessageID(body)
	c.logger.Debug("generated unique ID", "unique_id", uniqueID, "uid", msg.Uid)

	// Check if this message has already been downloaded using the unique ID
	if trackingManager != nil && c.config.Email.Tracking.TrackDownloaded {
		downloaded, err := trackingManager.IsEmailDownloaded(
			"IMAP",
			c.config.Email.Protocols.IMAP.Server,
			c.config.Email.Protocols.IMAP.Username,
			uniqueID,
		)
		if err != nil {
			c.logger.Warn("failed to check if email was downloaded",
				"unique_id", uniqueID,
				"error", err)
			// Continue processing this message
		} else if downloaded {
			c.logger.Debug("skipping already downloaded message", "unique_id", uniqueID)
			return nil // Skip this message
		}
	}

	// Process email content to extract attachments
	messageID := fmt.Sprintf("%d", msg.Uid)
	_, _, attachments, err := parser.ProcessEmailContent(body, messageID, c.logger)
	if err != nil {
		c.logger.Error("failed to process email content",
			"error", err,
			"uid", msg.Uid)
		
		// Log detailed error information
		if errorLogger != nil {
			errorLogger.LogError(errorlog.EmailError{
				Protocol:  "IMAP",
				Server:    c.config.Email.Protocols.IMAP.Server,
				Username:  c.config.Email.Protocols.IMAP.Username,
				MessageID: uniqueID,
				Sender:    sender,
				Subject:   subject,
				SentAt:    sentAt,
				ErrorTime: time.Now().UTC(),
				ErrorType: "process_email",
				ErrorMsg:  fmt.Sprintf("failed to process email content: %v", err),
				RawMessage: parser.GetRawMessageSample(body, 1000),
			})
		}
			
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
	var attachmentErrors []string
	
	for _, a := range attachments {
		if parser.IsAllowedAttachment(a.Filename, c.config.Email.Attachments.AllowedTypes, c.logger) {
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
						Protocol:  "IMAP",
						Server:    c.config.Email.Protocols.IMAP.Server,
						Username:  c.config.Email.Protocols.IMAP.Username,
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

			finalPath, err := parser.SaveAttachment(a.Filename, content, attachmentConfig, c.logger)
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
						Protocol:  "IMAP",
						Server:    c.config.Email.Protocols.IMAP.Server,
						Username:  c.config.Email.Protocols.IMAP.Username,
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

			savedAttachments = append(savedAttachments, filepath.Base(finalPath))
			c.logger.Info("saved attachment",
				"uid", msg.Uid,
				"filename", a.Filename,
				"path", finalPath)
		} else {
			c.logger.Debug("skipping disallowed attachment type",
				"filename", a.Filename)
		}
	}

	if len(attachmentErrors) > 0 {
		c.logger.Warn("encountered errors while processing attachments",
			"uid", msg.Uid,
			"error_count", len(attachmentErrors),
			"errors", strings.Join(attachmentErrors, "; "))
	}

	// Mark email as downloaded in tracking system
	if trackingManager != nil && c.config.Email.Tracking.TrackDownloaded {
		err := trackingManager.MarkEmailDownloaded(
			"IMAP",
			c.config.Email.Protocols.IMAP.Server,
			c.config.Email.Protocols.IMAP.Username,
			uniqueID,
			sender,
			subject,
			sentAt,
			len(savedAttachments),
		)
		if err != nil {
			c.logger.Warn("failed to mark email as downloaded",
				"unique_id", uniqueID,
				"error", err)
		}
	}

	// Delete message if configured
	if c.config.Email.Protocols.IMAP.DeleteAfterDownload {
		c.logger.Debug("marking message for deletion", "uid", msg.Uid)
		
		// Create a sequence set with just this message
		seqSet := new(imap.SeqSet)
		seqSet.AddNum(msg.SeqNum)
		
		// Add the \Deleted flag
		item := imap.FormatFlagsOp(imap.AddFlags, true)
		flags := []interface{}{imap.DeletedFlag}
		
		err := c.client.Store(seqSet, item, flags, nil)
		if err != nil {
			c.logger.Warn("failed to mark message for deletion",
				"uid", msg.Uid,
				"error", err)
		} else {
			// Expunge to actually remove the message
			if err := c.client.Expunge(nil); err != nil {
				c.logger.Warn("failed to expunge deleted messages",
					"error", err)
			}
		}
	}

	c.logger.Info("processed message",
		"uid", msg.Uid,
		"saved_attachments", len(savedAttachments),
		"error_attachments", len(attachmentErrors))

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
