package models

import "time"

type EmailConfig struct {
	Protocol            string `json:"protocol" yaml:"protocol"` // "imap" or "pop3"
	Server              string `json:"server" yaml:"server"`
	Port                int    `json:"port" yaml:"port"`
	Username            string `json:"username" yaml:"username"`
	Password            string `json:"password" yaml:"password"`
	EnableTLS           bool   `json:"enable_tls" yaml:"enable_tls"`
	DeleteAfterDownload bool   `json:"delete_after_download" yaml:"delete_after_download"`
	Folders             []string `json:"folders" yaml:"folders"`
}

type AttachmentConfig struct {
	AllowedTypes      []string `yaml:"allowed_types"`
	MaxSize           int64    `yaml:"max_size"`
	StoragePath       string   `yaml:"storage_path"`
	NamingPattern     string   `yaml:"naming_pattern"`
	PreserveStructure bool     `yaml:"preserve_structure"`
	SanitizeFilenames bool     `yaml:"sanitize_filenames"`
	HandleDuplicates  string   `yaml:"handle_duplicates,omitempty"`
}

type EmailFilter struct {
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`
}

type EmailDownloadRequest struct {
	Config EmailConfig `json:"config"`
	Filter EmailFilter `json:"filter,omitempty"`
	Async  bool        `json:"async"`
}

type DownloadResult struct {
	MessageID    string    `json:"message_id"`
	Subject      string    `json:"subject"`
	Attachments  []string  `json:"attachments"`
	DownloadedAt time.Time `json:"downloaded_at"`
	Status       string    `json:"status"`
	ErrorMessage string    `json:"error_message,omitempty"`
}
