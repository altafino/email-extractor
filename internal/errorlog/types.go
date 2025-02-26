package errorlog

import (
	"time"
)

// EmailError represents an error that occurred during email processing
type EmailError struct {
	ID          string    `json:"id"`
	ConfigID    string    `json:"config_id"`
	Protocol    string    `json:"protocol"`
	Server      string    `json:"server"`
	Username    string    `json:"username"`
	MessageID   string    `json:"message_id"`
	Sender      string    `json:"sender"`
	Subject     string    `json:"subject"`
	SentAt      time.Time `json:"sent_at"`
	ErrorTime   time.Time `json:"error_time"`
	ErrorType   string    `json:"error_type"`
	ErrorMsg    string    `json:"error_message"`
	RawMessage  string    `json:"raw_message,omitempty"`
}

// Logger defines the interface for email error logging
type Logger interface {
	// LogError records an email processing error
	LogError(err EmailError) error
	
	// GetErrors retrieves errors based on filters
	GetErrors(filters map[string]string) ([]EmailError, error)
	
	// CleanupOldErrors removes errors older than the retention period
	CleanupOldErrors() error
	
	// Close releases any resources used by the logger
	Close() error
} 