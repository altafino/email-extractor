package email

import "github.com/altafino/email-extractor/internal/types"

// Logger interface defines the logging methods we need
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// AttachmentHandler handles saving and processing of email attachments
type AttachmentHandler struct {
	logger Logger
	config *types.Config
}

// NewAttachmentHandler creates a new attachment handler
func NewAttachmentHandler(config *types.Config, logger Logger) *AttachmentHandler {
	return &AttachmentHandler{
		logger: logger,
		config: config,
	}
}
