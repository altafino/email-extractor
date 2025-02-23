# Configuration Setup

## Overview
The email-extractor service supports multiple email accounts through separate configuration files. Each account can have its own settings while sharing common configurations through a base template. Configuration files are managed outside of the Git repository and loaded through Docker Compose.

## Setup Steps

1. Create your configuration files:
   - Copy `config/default.config.yaml.template` to create new config files
   - Create one file per email account (e.g., `account1.config.yaml`, `account2.config.yaml`)
   - Place them in the `config/` directory

2. Update docker-compose.yml:
   - Mount the base template and account configuration files
   - Set CONFIG_FILES environment variable to list your config files
   - Each config file is mounted read-only for security

## Example Structure 
```
config/
├── templates/
│   └── base.yaml              # Base template with common settings
├── account1.config.yaml       # First email account configuration
└── account2.config.yaml       # Second email account configuration

docker-compose.yml             # Service configuration
.env                          # Environment variables
```

### Configuration Files

1. **base.yaml**: Template with common settings
   ```yaml
   meta:
     id: "base"
     name: "Base Template"
     template: ""
     enabled: true
   # ... common settings ...
   ```

2. **account1.config.yaml**: First account configuration
   ```yaml
   meta:
     id: "account1"
     name: "First Account"
     template: "base"
     enabled: true
   email:
     protocols:
       pop3:
         enabled: true
         server: "${POP3_SERVER_1}"
         username: "${POP3_USERNAME_1}"
         password: "${POP3_PASSWORD_1}"
   ```

3. **account2.config.yaml**: Second account configuration
   ```yaml
   meta:
     id: "account2"
     name: "Second Account"
     template: "base"
     enabled: true
   email:
     protocols:
       pop3:
         enabled: true
         server: "${POP3_SERVER_2}"
         username: "${POP3_USERNAME_2}"
         password: "${POP3_PASSWORD_2}"
   ```

4. **Environment Variables (.env)**
   ```env
   # First account
   POP3_SERVER_1=mail1.example.com
   POP3_USERNAME_1=user1@example.com
   POP3_PASSWORD_1=secure_password_1
   
   # Second account
   POP3_SERVER_2=mail2.example.com
   POP3_USERNAME_2=user2@example.com
   POP3_PASSWORD_2=secure_password_2
   
   ATTACHMENT_STORAGE_PATH=/data/attachments
   ``` 