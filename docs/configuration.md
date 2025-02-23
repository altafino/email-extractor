# Configuration Setup

## Overview
The email-extractor service supports multiple email accounts through separate configuration files. Each account can have its own settings while sharing common configurations through a base template. Configuration files are managed outside of the Git repository and loaded through Docker Compose.

## Setup Steps

1. Create the directory structure on the host:
   ```bash
   # Create required directories
   mkdir -p /opt/email-extractor/config/templates
   mkdir -p /opt/email-extractor/data/attachments
   
   # Set proper permissions
   chmod 755 /opt/email-extractor/data/attachments
   ```

2. Create your configuration files:
   - Copy `config/default.config.yaml.template` to create new config files
   - Create one file per email account (e.g., `account1.config.yaml`, `account2.config.yaml`)
   - Place them in the `config/` directory
   ```bash
   # Copy template files
   cp base.yaml /opt/email-extractor/config/templates/
   cp default.config.yaml.template /opt/email-extractor/config/default.config.yaml
   ```

3. Configure your settings:
   - Edit `/opt/email-extractor/config/default.config.yaml` with your email settings
   - The base template in `/opt/email-extractor/config/templates/base.yaml` contains common settings
   - Make sure storage paths point to `/data/attachments` inside the container

## Example Structure 
```
/opt/email-extractor/
├── config/
│   ├── templates/
│   │   └── base.yaml              # Base template with common settings
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
       storage_path: "/data/attachments"  # Fixed path inside container
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