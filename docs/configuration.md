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