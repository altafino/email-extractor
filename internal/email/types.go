package email

import (
	logger2 "github.com/altafino/email-extractor/internal/logger"
	"github.com/altafino/email-extractor/internal/types"
)

// AttachmentHandler handles saving and processing of email attachments
type AttachmentHandler struct {
	logger logger2.Logger
	config *types.Config
}

// NewAttachmentHandler creates a new attachment handler
func NewAttachmentHandler(config *types.Config, logger logger2.Logger) *AttachmentHandler {
	return &AttachmentHandler{
		logger: logger,
		config: config,
	}
}
