package attachment

import (
	"context"
	"fmt"

	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

// GDriveStorage implements AttachmentStorage for Google Drive
type GDriveStorage struct {
	logger   *slog.Logger
	service  *drive.Service
	parentID string // Google Drive folder ID where files will be stored
}

// NewGDriveStorage creates a new Google Drive storage instance
func NewGDriveStorage(ctx context.Context, logger *slog.Logger, credentialsFile, parentFolderID string) (AttachmentStorage, error) {
	service, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsFile))
	if err != nil {
		return nil, fmt.Errorf("failed to create Drive client: %w", err)
	}

	return &GDriveStorage{
		logger:   logger,
		service:  service,
		parentID: parentFolderID,
	}, nil
}

// Save implements AttachmentStorage.Save for Google Drive
func (gd *GDriveStorage) Save(filename string, content []byte, config AttachmentConfig) (string, error) {
	// Validate content size
	if int64(len(content)) > config.MaxSize {
		return "", fmt.Errorf("attachment size %d exceeds maximum allowed size %d", len(content), config.MaxSize)
	}

	// Process filename
	gd.logger.Debug("processing filename", "filename", filename)
	if config.SanitizeFilenames {
		filename = SanitizeFilename(filename)
	}
	gd.logger.Debug("sanitized filename", "filename", filename)

	// Apply the naming pattern
	now := time.Now().UTC()
	filename = GenerateFilename(filename, now, config.FilenamePattern)
	gd.logger.Debug("generated filename", "filename", filename)
	// Process storage path with date variables
	folderPath := config.StoragePath
	if strings.Contains(folderPath, "${") {
		folderPath = gd.processStoragePath(folderPath, now, config.AccountName)
	}

	// Create or get folder structure
	folderID, err := gd.ensureFolderStructure(folderPath, config.PreserveStructure)
	if err != nil {
		return "", fmt.Errorf("failed to ensure folder structure: %w", err)
	}

	// Create file metadata
	gd.logger.Debug("creating file metadata", "filename", filename, "folderID", folderID)
	file := &drive.File{
		Name:     filename,
		Parents:  []string{folderID},
		MimeType: gd.getMimeType(filename),
	}

	// Upload file
	reader := strings.NewReader(string(content))
	uploadedFile, err := gd.service.Files.Create(file).Media(reader).Do()
	if err != nil {
		return "", fmt.Errorf("failed to upload file: %w", err)
	}

	gd.logger.Debug("file uploaded successfully",
		"filename", filename,
		"id", uploadedFile.Id,
		"size", len(content))

	return uploadedFile.Id, nil
}

// Helper methods

func (gd *GDriveStorage) processStoragePath(path string, now time.Time, accountName string) string {
	replacements := map[string]string{
		"${YYYY}":    now.Format("2006"),
		"${YY}":      now.Format("06"),
		"${MM}":      now.Format("01"),
		"${DD}":      now.Format("02"),
		"${HH}":      now.Format("15"),
		"${mm}":      now.Format("04"),
		"${ss}":      now.Format("05"),
		"${account}": accountName,
	}

	for pattern, replacement := range replacements {
		path = strings.ReplaceAll(path, pattern, replacement)
	}

	return path
}

func (gd *GDriveStorage) ensureFolderStructure(path string, preserveStructure bool) (string, error) {
	if path == "" {
		return gd.parentID, nil
	}

	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	currentParentID := gd.parentID

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Search for existing folder
		query := fmt.Sprintf("name = '%s' and '%s' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false",
			part, currentParentID)

		fileList, err := gd.service.Files.List().Q(query).Fields("files(id)").Do()
		if err != nil {
			return "", fmt.Errorf("failed to search for folder: %w", err)
		}

		if len(fileList.Files) > 0 {
			currentParentID = fileList.Files[0].Id
			continue
		}

		// Create new folder
		folder := &drive.File{
			Name:     part,
			MimeType: "application/vnd.google-apps.folder",
			Parents:  []string{currentParentID},
		}

		createdFolder, err := gd.service.Files.Create(folder).Fields("id").Do()
		if err != nil {
			return "", fmt.Errorf("failed to create folder: %w", err)
		}

		currentParentID = createdFolder.Id
	}

	return currentParentID, nil
}

func (gd *GDriveStorage) getMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xls":
		return "application/vnd.ms-excel"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	default:
		return "application/octet-stream"
	}
}
