# Email Extractor

A service that automatically downloads emails and extracts attachments using POP3/IMAP protocols, with support for multiple accounts and extensive configuration options.

> **IMPORTANT NOTICE:** This project is currently in **Beta Stage** and should not be used in production environments. It is under active development with core functionality still being implemented and tested. Contributors are welcome to help improve stability and feature completeness.


## Features

### Email Processing
- [x] Multiple Account Support
- [x] Tracking of Processed Emails
- [x] POP3 Protocol Support
  - [x] TLS Support
  - [x] Custom Port Configuration
  - [ ] Delete After Download Option
- [x] IMAP Protocol Support
  - [x] TLS Support
  - [x] Custom Port Configuration
  - [ ] OAuth2 Support (in work)
- [x] Attachment Handling
  - [x] File Type Filtering (configurable)
  - [x] Size Limits (configurable)
  - [x] Custom Naming Patterns
  - [x] Date-based Directory Structure
  - [x] Duplicate File Handling
  - [x] Filename Sanitization
  - [x] Nested Attachment Scanning
  - [x] Storage Interface
    - [x] File Storage
    - [x] Google Drive
    - [ ] S3 compatible Bucket Storage
  - [x] Filter for TimePeriod IMAP
  - [x] Filter for TimePeriod POP3

### Security
- [x] TLS Configuration
  - [x] Minimum Version Control
  - [x] Certificate Verification
- [ ] OAuth2 Support (in work, for IMAP)
- [ ] API Security
  - [ ] API Key Authentication
  - [ ] IP Allowlisting
  - [ ] CORS Configuration
  - [ ] Rate Limiting

### Monitoring
- [ ] Health Checks
- [ ] Prometheus Metrics
- [ ] Tracing (Jaeger)
- [ ] Performance Profiling
- [ ] Alert System
  - [ ] Email Notifications
  - [ ] Configurable Thresholds
  - [ ] Error Rate Monitoring
  - [ ] Response Time Monitoring
  - [ ] Disk Usage Monitoring

### Configuration
- [x] Template-based Configuration
- [x] Environment Variable Support
- [x] Hot Reload Support
- [x] Validation
  - [x] Required Fields
  - [x] Value Ranges
  - [x] File Extensions
  - [x] Path Validation

### Logging
- [x] Structured Logging (JSON/Text)
- [x] Log Levels
- [x] Caller Information
- [ ] Sensitive Data Redaction
- [ ] Log Rotation
  - [ ] Size-based Rotation
  - [ ] Age-based Retention
  - [ ] Compression

### Scheduling
- [x] Configurable Intervals
- [x] Immediate Start Option
- [x] Start/Stop Times
- [x] Multiple Schedule Support

## Installation

1. Create required directories:
```bash
mkdir -p /opt/email-extractor/{config/templates,data/attachments}
chmod 755 /opt/email-extractor/data/attachments
```

2. Copy configuration files:
```bash
cp config/templates/base.yaml /opt/email-extractor/config/templates/
cp config/default.config.yaml.template /opt/email-extractor/config/default.config.yaml
```

3. Configure your settings (see [Configuration Guide](docs/configuration.md))

4. Run with Docker:
```bash
docker-compose up -d
```

## Configuration

See the [Configuration Guide](docs/configuration.md) for detailed setup instructions.

## Environment Variables

Essential variables:
```env
POP3_SERVER=mail.example.com
POP3_USERNAME=user@example.com
POP3_PASSWORD=secure_password
ATTACHMENT_STORAGE_PATH=/data/attachments
```

Optional monitoring variables:
```env
ALERT_EMAIL=alerts@example.com
JAEGER_ENDPOINT=http://jaeger:14268/api/traces
LOG_FILE_PATH=/var/log/email-extractor.log
```

## Health Check

The service provides a health check endpoint:
```bash
curl http://localhost:9999/health
```

## Metrics

When enabled, metrics are available at:
```bash
curl http://localhost:9999/metrics
```

## Development Status

Current Version: 0.1.0

The service is in active development with core functionality working:
- [x] Basic email processing
- [x] Attachment extraction
- [x] Configuration management
- [x] Monitoring setup
- [x] IMAP support
- [ ] OAuth2 integration (planned)
- [ ] Web UI (planned)
- [ ] API (planned)

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## OAuth2 Authentication

Email Extractor now supports OAuth2 authentication for IMAP servers. This provides a more secure way to authenticate with email providers like Gmail and Microsoft Outlook without storing your password.

### Configuration

To use OAuth2 authentication, update your configuration file as follows:

```yaml
email:
  protocols:
    imap:
      # ... other settings ...
      security:
        oauth2:
          enabled: true
          provider: "google"  # or "microsoft"
          client_id: "your-client-id"
          client_secret: "your-client-secret"
          token_storage_path: "/path/to/tokens"
```

### Obtaining OAuth2 Credentials

#### For Google:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Select "Desktop app" as the application type
6. Enter a name for your client ID
7. Copy the Client ID and Client Secret to your configuration file
8. **Important**: Add `http://localhost:8085/oauth/callback` as an authorized redirect URI

#### For Microsoft:

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" > "App registrations"
3. Click "New registration"
4. Enter a name for your application
5. Select "Accounts in any organizational directory and personal Microsoft accounts"
6. Set the redirect URI to `http://localhost:8085/oauth/callback`
7. Click "Register"
8. Copy the Application (client) ID to your configuration file
9. Navigate to "Certificates & secrets"
10. Create a new client secret and copy it to your configuration file

### Managing OAuth2 Tokens

Email Extractor provides CLI commands to manage OAuth2 tokens:

#### Generate a token:

```
email-extractor oauth2 generate default
```

This will open a browser window to authenticate with the provider. After authentication, you'll be redirected to a local page confirming the success.

#### List tokens:

```
email-extractor oauth2 list
```

#### Delete a token:

```
email-extractor oauth2 delete default
```

### Automatic Token Refresh

OAuth2 tokens are automatically refreshed when they expire, so you don't need to manually regenerate them.