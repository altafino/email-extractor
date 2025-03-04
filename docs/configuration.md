# Configuration Setup

## Overview
The email-extractor service supports multiple email accounts and different storage backends for attachments. It uses a flexible configuration system based on YAML files and environment variables.

## Setup Steps

1. Create the directory structure on the host:
   ```bash
   # Create required directories
   mkdir -p /opt/email-extractor/config/templates
   mkdir -p /opt/email-extractor/data/attachments
   mkdir -p /opt/email-extractor/config/keys # For Google Drive credentials
   
   # Set proper permissions
   chmod 755 /opt/email-extractor/data/attachments
   ```

2. Create your configuration files:
   - Copy `config/default.config.yaml.template` to create new config files
   - Create one file per email account (e.g., `account1.config.yaml`, `account2.config.yaml`)
   - Place them in the `/opt/email-extractor/config/` directory
   - Copy `config/templates/base.yaml` to `/opt/email-extractor/config/templates/`
   ```bash
   # Copy template files
   cp config/templates/base.yaml /opt/email-extractor/config/templates/
   cp config/default.config.yaml.template /opt/email-extractor/config/default.config.yaml
   ```

3. Configure your settings:
   - Edit `/opt/email-extractor/config/default.config.yaml` with your email and storage settings
   - The base template in `/opt/email-extractor/config/templates/base.yaml` contains common settings

## Example Structure 
```
/opt/email-extractor/
├── config/
│   ├── templates/
│   │   └── base.yaml              # Base template with common settings
│   ├── keys/                      # Google Drive credentials (JSON files)
│   │   └── your-credentials.json
│   └── default.config.yaml        # Main configuration file
└── data/
    └── attachments/               # Where email attachments are stored
```

### Configuration Files

1. **base.yaml**: Template with common settings
   ```yaml
   meta:
     id: "base"
     name: "Base Template"
     template: ""
     enabled: true
   email:
     attachments:
       allowed_types:
         - ".pdf"
         - ".xml"
         # ... other types ...
   ```

2. **default.config.yaml**: Main configuration
   ```yaml
   meta:
     id: "default"
     name: "Default Account"
     template: "base"
     enabled: true
   email:
     protocols:
       pop3:
         enabled: true
         server: "${POP3_SERVER}"
         username: "${POP3_USERNAME}"
         password: "${POP3_PASSWORD}"
     attachments:
       storage_path: "/data/attachments/${account}_${YYYY}_${MM}_${DD}" # Container path!
       naming_pattern: "${unixtime}_${filename}"
       preserve_structure: true
       scan_nested: true
       sanitize_filenames: true
       handle_duplicates: "increment"
       storage:
         type: "gdrive"  # Or "file" for local filesystem
         credentials_file: "/config/keys/your-credentials.json"  # Container path!
         parent_folder_id: "your_google_drive_folder_id" # Required for GDrive
   ```

3. **Environment Variables (.env)**
   ```env
   # Email settings
   POP3_SERVER=mail.example.com
   POP3_USERNAME=user@example.com
   POP3_PASSWORD=secure_password
   
   # Optional monitoring settings
   ALERT_EMAIL=alerts@example.com
   JAEGER_ENDPOINT=http://jaeger:14268/api/traces
   ```

## Storage Configuration

The `email.attachments.storage` section in `default.config.yaml` controls where attachments are saved.

*   **`type`**:  Specifies the storage backend.  Currently supported values:
    *   `"file"`:  Saves attachments to the local filesystem (within the container).
    *   `"gdrive"`: Saves attachments to Google Drive.
*   **`storage_path`**:
    *   **For `type: "file"`:**  This is the directory *inside the container* where attachments will be stored.  You *must* use `/data/attachments` as the base path, and it will be mapped to `/opt/email-extractor/data/attachments` on the host. You can use date/account variables (e.g., `${YYYY}`, `${account}`).
    *   **For `type: "gdrive"`:** This field is used to create folder.
*   **`credentials_file`**:  (Required for `type: "gdrive"`) The path *inside the container* to the Google Drive service account credentials JSON file.  You should place this file in `/opt/email-extractor/config/keys/` on the host, and it will be mounted to `/config/keys/` inside the container.
*   **`parent_folder_id`**: (Required for `type: "gdrive"`) The ID of the Google Drive folder where attachments should be stored.

## Scheduling Configuration

The `scheduling` section in your configuration file controls when and how often the service checks for new emails.

### Basic Settings

```yaml
scheduling:
  enabled: true                     # Enable or disable scheduling
  frequency_every: "minute"         # Time unit (minute, hour, day, week, month)
  frequency_amount: 5               # Run every X units of time
  start_now: false                  # Whether to run immediately on startup
  start_at: "2024-03-15T00:00:00Z"  # When to start scheduling (RFC3339 format)
  stop_at: "2025-12-31T23:59:59Z"   # When to stop scheduling (RFC3339 format)
```

### Configuration Options

- **`enabled`**: Set to `true` to enable scheduled email downloads, or `false` to disable.
- **`frequency_every`**: The time unit for scheduling. Valid values:
  - `minute`: Schedule by minutes
  - `hour`: Schedule by hours
  - `day`: Schedule by days
  - `week`: Schedule by weeks
  - `month`: Schedule by months
- **`frequency_amount`**: How many units of time between runs (e.g., `5` with `frequency_every: "minute"` means run every 5 minutes)

### Start and Stop Controls

- **`start_now`**: When `true`, the job will run immediately when the service starts, then follow the schedule. When `false`, it will wait until the specified `start_at` time.
- **`start_at`**: The date and time to start the scheduled job (in RFC3339 format: `YYYY-MM-DDTHH:MM:SSZ`). Required if `start_now` is `false`.
- **`stop_at`**: Optional date and time to stop the scheduled job (in RFC3339 format). After this time, the job will no longer run.

### Frequency Limits

Each frequency type has maximum limits:
- `minute`: Maximum 60 (once per minute to once per hour)
- `hour`: Maximum 24 (once per hour to once per day)
- `day`: Maximum 31 (once per day to once per month)
- `week`: Maximum 52 (once per week to once per year)
- `month`: Maximum 12 (once per month to once per year)

### Examples

#### Run Every 15 Minutes Starting Immediately

```yaml
scheduling:
  enabled: true
  frequency_every: "minute"
  frequency_amount: 15
  start_now: true
```

#### Run Daily at a Specific Time

```yaml
scheduling:
  enabled: true
  frequency_every: "day"
  frequency_amount: 1
  start_now: false
  start_at: "2024-03-15T08:00:00Z"  # Start at 8:00 AM UTC
```

#### Run Weekly with an End Date

```yaml
scheduling:
  enabled: true
  frequency_every: "week"
  frequency_amount: 1
  start_now: false
  start_at: "2024-03-18T09:00:00Z"  # Start on Monday at 9:00 AM UTC
  stop_at: "2024-12-31T23:59:59Z"   # Stop at the end of the year
```

### Important Notes

- All times must be in UTC and use RFC3339 format (`YYYY-MM-DDTHH:MM:SSZ`)
- If `start_now` is `false`, you must provide a valid `start_at` time
- If `start_at` is in the past when the service starts, the scheduler will use the next occurrence based on the frequency
- If `stop_at` is provided and is in the past, the job will not be scheduled
- The scheduler automatically handles service restarts and will resume based on the configured schedule

## Docker Compose Configuration
```yaml
services:
  email-service:
    volumes:
      - type: bind
        source: /opt/email-extractor/config/templates/base.yaml
        target: /app/config/templates/base.yaml
        read_only: true
      - type: bind
        source: /opt/email-extractor/config/default.config.yaml
        target: /app/config/default.config.yaml
        read_only: true
      - type: bind
        source: /opt/email-extractor/data/attachments
        target: /data/attachments
      - type: bind
        source: /opt/email-extractor/config/keys
        target: /config/keys
        read_only: true
    environment:
      - CONFIG_FILES=default.config.yaml
      - ATTACHMENT_STORAGE_PATH=/data/attachments
```

## Important Notes
- All paths in configuration files should use `/data/attachments` (container path)
- Host storage is in `/opt/email-extractor/data/attachments`
- Configuration files are mounted read-only for security
- Attachments directory needs proper permissions (755)
- The service automatically creates date-based subdirectories for attachments 
- **Google Drive Credentials:** For Google Drive, obtain a service account key JSON file and place it in `/opt/email-extractor/config/keys/` on your host machine. 