package parser

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"mime"
	"mime/quotedprintable"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/altafino/email-extractor/internal/utility/u_io"

	"github.com/DusanKasan/parsemail"
	"github.com/jhillyerd/enmime/mediatype"
)

// SaveAttachmentToFile saves attachment data to a file
func SaveAttachmentToFile(data []byte, filename string, outputDir string, logger *slog.Logger) (string, error) {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// Clean filename to remove any potentially dangerous characters
	safeFilename := u_io.CleanFilename(filename)

	// Ensure filename is not empty
	if safeFilename == "" {
		safeFilename = fmt.Sprintf("attachment_%d%s", time.Now().UnixNano(), ".bin")
	}

	// Create full path
	outputPath := filepath.Join(outputDir, safeFilename)

	// Check if file already exists, append number if it does
	outputPath = u_io.EnsureUniqueFilename(outputPath)

	// Write file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write attachment file: %w", err)
	}

	logger.Debug("saved attachment", "filename", safeFilename, "path", outputPath)
	return outputPath, nil
}

// ExtractAttachmentsMultipart extracts attachments from multipart content
func ExtractAttachmentsMultipart(content []byte, boundary string, logger *slog.Logger) ([]parsemail.Attachment, error) {
	// Skip preamble and find first boundary
	boundaryBytes := []byte("--" + boundary)
	if idx := bytes.Index(content, boundaryBytes); idx != -1 {
		content = content[idx:]
	}

	// Function to handle nested multipart content
	var handleMultipart func([]byte, string) ([]parsemail.Attachment, error)
	handleMultipart = func(content []byte, boundary string) ([]parsemail.Attachment, error) {
		var nestedAttachments []parsemail.Attachment
		var currentPart []byte
		var inHeader bool = true
		var headers map[string][]string = make(map[string][]string)

		parts := bytes.Split(content, boundaryBytes)
		for _, part := range parts[1:] { // Skip the first empty part
			if bytes.HasPrefix(part, []byte("--")) {
				break // End boundary
			}

			// Split headers and body
			lines := bytes.Split(bytes.TrimSpace(part), []byte("\n"))
			inHeader = true
			headers = make(map[string][]string)
			currentPart = nil
			var bodyStart int

			for i, line := range lines {
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					inHeader = false
					bodyStart = i + 1
					continue
				}

				if inHeader {
					if idx := bytes.Index(line, []byte(":")); idx > 0 {
						key := string(bytes.TrimSpace(line[:idx]))
						value := string(bytes.TrimSpace(line[idx+1:]))
						headers[key] = append(headers[key], value)
					}
				}
			}

			// Join body lines with original line endings
			if bodyStart < len(lines) {
				currentPart = bytes.Join(lines[bodyStart:], []byte("\n"))
			}

			// Process the part based on headers
			contentType := ""
			if ct, ok := headers["Content-Type"]; ok && len(ct) > 0 {
				contentType = ct[0]
			}

			mediaType, params, invalidParams, err := mediatype.Parse(contentType)
			logger.Debug("mediaType", "mediaType", mediaType, "params", params, "invalidParams", invalidParams, "err", err)
			if err == nil {
				// Handle nested multipart
				if strings.Contains(strings.ToLower(mediaType), "multipart") {
					if nestedBoundary := params["boundary"]; nestedBoundary != "" {
						// Clean up nested content before processing
						if idx := bytes.Index(currentPart, []byte("--"+nestedBoundary)); idx != -1 {
							currentPart = currentPart[idx:]
						}
						nested, err := handleMultipart(currentPart, nestedBoundary)
						if err == nil {
							nestedAttachments = append(nestedAttachments, nested...)
						}
						continue
					}
				}

				// Check for attachment
				contentDisp := ""
				if cd, ok := headers["Content-Disposition"]; ok && len(cd) > 0 {
					contentDisp = cd[0]
				}

				filename := ""
				if contentDisp != "" {
					if _, params, _, err := mediatype.Parse(contentDisp); err == nil {
						if fn, ok := params["filename"]; ok {
							filename = DecodeFilename(fn)
						}
					}
				}

				// If no filename from disposition, try Content-Type name parameter
				if filename == "" && params["name"] != "" {
					filename = DecodeFilename(params["name"])
				}

				// Determine if this part is an attachment
				isAttachment := false
				if contentDisp != "" {
					isAttachment = strings.Contains(contentDisp, "attachment") || strings.Contains(contentDisp, "inline")
				} else {
					isAttachment = strings.HasPrefix(mediaType, "application/") ||
						strings.HasPrefix(mediaType, "image/") ||
						strings.Contains(mediaType, "pdf") ||
						strings.Contains(mediaType, "xml") ||
						strings.Contains(mediaType, "msword") ||
						strings.Contains(mediaType, "excel") ||
						strings.Contains(mediaType, "spreadsheet") ||
						strings.Contains(mediaType, "document") ||
						strings.Contains(mediaType, "text") ||
						strings.Contains(mediaType, "audio") ||
						strings.Contains(mediaType, "video") ||
						strings.Contains(mediaType, "application") ||
						strings.Contains(mediaType, "zip") ||
						strings.Contains(mediaType, "tar") ||
						strings.Contains(mediaType, "gz") ||
						strings.Contains(mediaType, "bz2") ||
						strings.Contains(mediaType, "7z") ||
						strings.Contains(mediaType, "rar")
				}

				if isAttachment && len(currentPart) > 0 {
					// Trim any trailing boundary markers
					if idx := bytes.Index(currentPart, []byte("\n--")); idx != -1 {
						currentPart = currentPart[:idx]
					}

					// Handle content encoding
					if ce, ok := headers["Content-Transfer-Encoding"]; ok && len(ce) > 0 {
						decoded, err := DecodeContent(currentPart, ce[0])
						if err == nil {
							currentPart = decoded
						}
					}

					// Generate filename if needed
					if filename == "" {
						ext := ".bin"
						if mimeExt, ok := MimeToExt[mediaType]; ok {
							ext = mimeExt
						}
						// Just use a simple base name for attachments without names
						filename = fmt.Sprintf("attachment%s", ext)
					} else {
						// For existing filenames, just trim spaces
						filename = strings.TrimSpace(filename)
					}

					nestedAttachments = append(nestedAttachments, parsemail.Attachment{
						Filename: filename,
						Data:     bytes.NewReader(currentPart),
					})
				}
			}
		}
		return nestedAttachments, nil
	}

	logger.Debug("starting multipart extraction", "boundary", boundary)
	return handleMultipart(content, boundary)
}

// DecodeContent decodes content based on the specified encoding
func DecodeContent(content []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "base64":
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(content)))
		n, err := base64.StdEncoding.Decode(decoded, content)
		if err != nil {
			return nil, err
		}
		return decoded[:n], nil

	case "quoted-printable":
		reader := quotedprintable.NewReader(bytes.NewReader(content))
		return io.ReadAll(reader)

	case "7bit", "8bit", "binary", "":
		return content, nil

	default:
		return content, nil
	}
}

// DecodeFilename decodes RFC 2047 encoded-word syntax in filenames
func DecodeFilename(filename string) string {
	decoder := mime.WordDecoder{}
	decoded, err := decoder.DecodeHeader(filename)
	if err != nil {
		// If decoding fails, return the original filename
		return filename
	}
	return decoded
}

// ParseEmail parses an email with fallback mechanisms
func ParseEmail(content []byte, logger *slog.Logger) (parsemail.Email, error) {
	var email parsemail.Email
	var err error

	// Try to parse the email
	email, err = parsemail.Parse(bytes.NewReader(content))
	if err != nil {
		// Check for specific error types
		if strings.Contains(err.Error(), "multipart: NextPart: EOF") {
			logger.Debug("handling multipart EOF error, attempting fallback parsing")
			// Try fallback parsing method for malformed multipart messages
			return ParseEmailFallback(content, logger)
		} else if strings.Contains(err.Error(), "mime: invalid media parameter") {
			logger.Debug("handling invalid media parameter error, attempting fallback parsing")
			// Try fallback parsing method for invalid MIME parameters
			return ParseEmailFallback(content, logger)
		}
		return email, err
	}

	return email, nil
}

// ParseEmailFallback provides a fallback method for parsing problematic emails
func ParseEmailFallback(content []byte, logger *slog.Logger) (parsemail.Email, error) {
	// This would be your fallback implementation
	// For now, returning an empty email structure
	return parsemail.Email{}, nil
}

// MimeToExt maps MIME types to file extensions
var MimeToExt = map[string]string{
	"application/pdf":          ".pdf",
	"application/msword":       ".doc",
	"application/vnd.ms-excel": ".xls",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   ".docx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         ".xlsx",
	"application/vnd.ms-powerpoint":                                             ".ppt",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
	"image/jpeg":                   ".jpg",
	"image/png":                    ".png",
	"image/gif":                    ".gif",
	"image/bmp":                    ".bmp",
	"image/tiff":                   ".tiff",
	"text/plain":                   ".txt",
	"text/html":                    ".html",
	"text/csv":                     ".csv",
	"text/xml":                     ".xml",
	"audio/mpeg":                   ".mp3",
	"audio/wav":                    ".wav",
	"video/mp4":                    ".mp4",
	"video/mpeg":                   ".mpeg",
	"video/quicktime":              ".mov",
	"application/zip":              ".zip",
	"application/x-tar":            ".tar",
	"application/x-gzip":           ".gz",
	"application/x-bzip2":          ".bz2",
	"application/x-7z-compressed":  ".7z",
	"application/x-rar-compressed": ".rar",
}

// IsAllowedAttachment checks if a file with the given filename is allowed based on its extension
func IsAllowedAttachment(filename string, allowedTypes []string, logger *slog.Logger) bool {
	if filename == "" {
		logger.Debug("empty filename", "filename", filename)
		return false
	}

	ext := filepath.Ext(filename)
	if ext == "" {
		logger.Debug("no extension", "filename", filename)
		return false
	}

	ext = strings.ToLower(ext)
	logger.Debug("checking attachment",
		"filename", filename,
		"extension", ext,
		"allowed_types", allowedTypes)

	for _, allowedType := range allowedTypes {
		allowedType = strings.ToLower(allowedType)
		// Compare with and without dot
		if ext == allowedType ||
			ext == "."+strings.TrimPrefix(allowedType, ".") ||
			strings.TrimPrefix(ext, ".") == strings.TrimPrefix(allowedType, ".") {
			logger.Debug("allowed attachment", "filename", filename, "extension", ext)
			return true
		}
	}

	logger.Debug("attachment not allowed", "filename", filename, "extension", ext)
	return false
}

// SaveAttachment saves attachment content to a file with proper naming and permissions
func SaveAttachment(filename string, content []byte, config AttachmentConfig, logger *slog.Logger) (string, error) {
	// Validate content size
	if int64(len(content)) > config.MaxSize {
		return "", fmt.Errorf("attachment size %d exceeds maximum allowed size %d", len(content), config.MaxSize)
	}

	// First sanitize if configured (before pattern application)
	if config.SanitizeFilenames {
		filename = SanitizeFilename(filename)
	}

	// Apply the naming pattern
	filename = GenerateFilename(filename, time.Now().UTC(), config.FilenamePattern)

	// Ensure filename has correct extension
	ext := strings.ToLower(filepath.Ext(filename))
	baseFilename := strings.TrimSuffix(filename, ext)

	// If the extension is uppercase, convert it to lowercase
	if ext != strings.ToLower(ext) {
		filename = baseFilename + strings.ToLower(ext)
	}

	// If no extension, try to detect from content
	if ext == "" {
		contentType := http.DetectContentType(content)
		if mimeExt, ok := MimeToExt[contentType]; ok {
			filename = filename + mimeExt
			ext = mimeExt
		}
	}

	// Sanitize filename if configured
	if config.SanitizeFilenames {
		filename = SanitizeFilename(filename)
	}

	if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create storage directory: %w", err)
	}

	var finalPath string
	if config.PreserveStructure {
		// Create date-based subdirectories
		dateDir := time.Now().UTC().Format("2006/01/02")
		fullDir := filepath.Join(config.StoragePath, dateDir)
		if err := os.MkdirAll(fullDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create date directory: %w", err)
		}
		finalPath = filepath.Join(fullDir, filename)
	} else {
		finalPath = filepath.Join(config.StoragePath, filename)
	}
	logger.Debug("final path", "path", finalPath)

	// Check if file already exists
	if _, err := os.Stat(finalPath); err == nil {
		// File exists, append timestamp to filename
		ext := filepath.Ext(finalPath)
		base := strings.TrimSuffix(finalPath, ext)
		// Ensure we have an extension
		if ext == "" {
			ext = filepath.Ext(filename)
		}
		finalPath = fmt.Sprintf("%s_%d%s", base, time.Now().UnixNano(), ext)
	}

	// Create file with restricted permissions
	f, err := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	// Write content
	if _, err := f.Write(content); err != nil {
		os.Remove(finalPath) // Clean up on error
		return "", fmt.Errorf("failed to write file content: %w", err)
	}

	return finalPath, nil
}

// SanitizeFilename removes potentially dangerous characters from filenames
func SanitizeFilename(filename string) string {
	// Remove any path components
	filename = filepath.Base(filename)

	// Replace potentially problematic characters
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		";", "_",
		"&", "_",
		"$", "_",
		"#", "_",
		"%", "_",
		"@", "_",
		"!", "_",
		"`", "_",
		"~", "_",
		"^", "_",
		"(", "_",
		")", "_",
		"[", "_",
		"]", "_",
		"{", "_",
		"}", "_",
		"'", "_",
		"\n", "_",
		"\r", "_",
		"\t", "_",
	)
	filename = replacer.Replace(filename)

	// Limit filename length
	const maxLength = 255
	if len(filename) > maxLength {
		ext := filepath.Ext(filename)
		base := filename[:maxLength-len(ext)]
		filename = base + ext
	}

	return filename
}

// GenerateFilename applies a naming pattern to a filename
func GenerateFilename(filename string, timestamp time.Time, pattern string) string {
	if pattern == "" {
		return filename
	}

	// Extract base name and extension
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)

	// Apply pattern
	result := pattern
	result = strings.ReplaceAll(result, "{filename}", base)
	result = strings.ReplaceAll(result, "{ext}", strings.TrimPrefix(ext, "."))
	result = strings.ReplaceAll(result, "{date}", timestamp.Format("2006-01-02"))
	result = strings.ReplaceAll(result, "{time}", timestamp.Format("150405"))
	result = strings.ReplaceAll(result, "{datetime}", timestamp.Format("20060102_150405"))
	result = strings.ReplaceAll(result, "{unixtime}", fmt.Sprintf("%d", timestamp.UnixNano()))
	result = strings.ReplaceAll(result, "{random}", fmt.Sprintf("%d", rand.Intn(10000)))

	// If the pattern doesn't include the extension, add it
	if !strings.Contains(pattern, "{ext}") && !strings.HasSuffix(result, ext) {
		result += ext
	}

	return result
}

// AttachmentConfig holds configuration for attachment handling
type AttachmentConfig struct {
	StoragePath       string
	MaxSize           int64
	AllowedTypes      []string
	SanitizeFilenames bool
	PreserveStructure bool
	FilenamePattern   string
}
