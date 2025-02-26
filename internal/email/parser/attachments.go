package parser

import (
	"log/slog"

	"github.com/yourusername/yourproject/internal/parsemail"
)

// ExtractAttachmentsMultipart extracts attachments from multipart content
func ExtractAttachmentsMultipart(content []byte, boundary string, logger *slog.Logger) ([]parsemail.Attachment, error) {
	// Existing extractAttachmentsMultipart implementation
}

// ParseEmail parses an email with fallback mechanisms
func ParseEmail(content []byte, logger *slog.Logger) (parsemail.Email, error) {
	// Existing parseEmail implementation
}

// DecodeFilename decodes MIME-encoded filenames
func DecodeFilename(filename string) string {
	// Existing decodeFilename implementation
}
