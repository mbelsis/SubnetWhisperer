# Subnet Whisperer

![Subnet Whisperer Logo](generated-icon.png)

A powerful web-based tool for scanning subnets, executing commands via SSH, and analyzing results with multi-threading support. Featuring secure credential storage, scheduled scanning, and comprehensive server profiling capabilities.


## Features

- **User Authentication**: Login-protected interface with user management and role-based access control
- **Subnet Scanning**: Scan multiple IP addresses or subnets in parallel
- **SSH Connection**: Connect to remote hosts using password or key-based authentication
- **Command Execution**: Run custom commands or use predefined templates
- **Server Profiling**: Collect basic or detailed information about remote servers
- **Result Analysis**: View and filter scan results with charts and statistics
- **Export Capabilities**: Export results in CSV, JSON, or PDF format
- **Scheduled Scans**: Set up recurring scans to automate subnet monitoring
- **Multi-threading**: Perform parallel scanning for efficient operations
- **Secure Credential Storage**: Store SSH credentials with Fernet symmetric encryption
- **Multiple Credential Sets**: Save and manage multiple credential sets with auto-try functionality
- **Customizable Theme**: Switch between dark and light mode with smooth transitions

## System Requirements

- Python 3.10+
- SQLite or PostgreSQL database
- Basic understanding of SSH and network operations

## Project Structure

```
subnet_whisperer/
├── instance/                  # Database files
│   └── subnet_whisperer.db
├── static/                    # Static assets
│   ├── css/
│   │   ├── custom.css        # Custom styling
│   │   └── theme.css         # Dark/light theme support
│   └── js/
│       ├── main.js           # Common utility functions
│       ├── results.js        # Results page functionality
│       ├── scan.js           # Scan page functionality
│       └── theme.js          # Theme switching functionality
├── templates/                 # HTML templates
│   ├── 404.html
│   ├── 500.html
│   ├── base.html             # Base template with common elements
│   ├── change_password.html  # Password change page
│   ├── credentials.html      # Credential management page
│   ├── index.html            # Home page
│   ├── login.html            # Login page
│   ├── results.html          # Results viewing page
│   ├── scan.html             # Scan configuration page
│   ├── schedule_form.html    # Schedule creation/editing
│   ├── schedule_detail.html  # Schedule details
│   ├── schedules.html        # Schedule management
│   ├── settings.html         # Application settings
│   ├── templates.html        # Command templates management
│   └── users.html            # User management page (admin)
├── app.py                    # Flask application and routes
├── encryption_utils.py       # Secure encryption for credentials
├── forms.py                  # Form definitions
├── main.py                   # Application entry point
├── run_migrations.py         # Database migration script
├── models.py                 # Database models (User, ScanSession, etc.)
├── scheduler.py              # Background scheduler for recurring scans
├── setup.sh                  # Installation script
├── ssh_utils.py              # SSH connection utilities
└── subnet_utils.py           # Subnet parsing utilities
```

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- For SSH operations: 
  - Linux: No additional packages needed (uses built-in SSH capabilities)
  - macOS: No additional packages needed (uses built-in SSH capabilities)
  - Windows: Microsoft Visual C++ 14.0 or greater is required for some dependencies

### Option 1: Using the Setup Script (Recommended)

The setup script will:
- Install all required Python packages
- Set up the SQLite database (default)
- Create necessary directories
- Configure basic environment variables
- Create a default admin account

Steps:
1. Clone the repository
2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
3. A default admin account is created automatically:
   - **Username:** `admin`
   - **Password:** `admin`

> **Important:** Change the default admin password immediately after your first login via the user dropdown menu in the top-right corner.

### Option 2: Manual Installation

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install flask flask-login flask-sqlalchemy flask-wtf gunicorn matplotlib pandas paramiko psycopg2-binary sqlalchemy wtforms email-validator cryptography bcrypt
   ```
4. Create the instance and logs directories:
   ```bash
   mkdir -p instance logs
   ```
5. Initialize the database and create the default admin account:
   ```bash
   python run_migrations.py
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```
   The database initialization automatically creates a default admin account:
   - **Username:** `admin`
   - **Password:** `admin`

> **Important:** Change the default admin password immediately after your first login via the user dropdown menu in the top-right corner.

## Docker Deployment

Subnet Whisperer can be easily deployed using Docker, which provides a consistent and isolated environment for running the application.

### Option 1: Using Docker Compose (Recommended)

You can also use the provided Makefile for common operations:

```bash
# Build the Docker image
make build

# Run with SQLite
make run

# Run with PostgreSQL
make run-postgres

# Stop containers
make stop

# Clean up (stop containers and remove volumes)
make clean
```


This method sets up both the application and an optional PostgreSQL database:

1. Make sure Docker and Docker Compose are installed on your system
2. Run the application with SQLite (default):
   ```bash
   ./docker-start.sh
   ```
   Or with PostgreSQL:
   ```bash
   ./docker-start.sh postgres
   ```
3. Access the application at http://localhost:5000
4. Log in with the default admin account:
   - **Username:** `admin`
   - **Password:** `admin`

> **Important:** Change the default admin password immediately after your first login via the user dropdown menu in the top-right corner.

### Option 2: Using Docker directly

If you prefer to run only the application container:

1. Build the Docker image:
   ```bash
   docker build -t subnet-whisperer .
   ```
2. Run the container:
   ```bash
   docker run -p 5000:5000 -v $(pwd)/instance:/app/instance -v $(pwd)/logs:/app/logs subnet-whisperer
   ```
3. Log in with the default admin account:
   - **Username:** `admin`
   - **Password:** `admin`

> **Important:** Change the default admin password immediately after your first login.

### Using Environment Variables with Docker
For convenience, you can use the provided environment file template:

```bash
# Copy the example to create your own environment file
cp .env.example .env

# Edit the file with your settings
nano .env

# Run with your environment variables
docker-compose --env-file .env up
```


You can configure the application with environment variables:

```bash
# Use PostgreSQL
docker run -p 5000:5000 \
  -e DATABASE_URL="postgresql://user:password@host/dbname" \
  -e ENCRYPTION_KEY="your-secure-key" \
  -e FLASK_SECRET_KEY="your-flask-secret" \
  -v $(pwd)/instance:/app/instance \
  -v $(pwd)/logs:/app/logs \
  subnet-whisperer
```

### Docker Image Security

The Docker image includes:
- Minimal base image (python:3.11-slim)
- Only necessary system dependencies
- No development tools in the final image
- Non-root user execution for better security

### Persistent Storage

The following directories are persisted as volumes:
- `instance/`: Contains the SQLite database (if used) and encryption keys
- `logs/`: Contains application logs

When using PostgreSQL, the database data is stored in a named Docker volume.


## Running the Application

```bash
python main.py
```

The application will be available at http://localhost:5000

### Default Admin Account

On first run, a default admin account is created automatically:
- **Username:** `admin`
- **Password:** `admin`

> **Important:** Change the default admin password immediately after your first login. Navigate to the user dropdown in the top-right corner and select "Change Password".

## Database Setup

### Understanding the Database Architecture

Subnet Whisperer uses SQLAlchemy as the Object-Relational Mapping (ORM) layer to interact with databases. Here's a quick explanation of the components:

- **SQLAlchemy**: This is a Python library that provides an interface between Python code and databases. It's not a database itself but a tool that allows our application to work with different database systems through the same Python API.

- **Database Backends**: The application supports two database backends:
  - SQLite (default): A file-based, lightweight database
  - PostgreSQL (optional): A more powerful, client-server database system

The application code remains the same regardless of which database backend you choose. SQLAlchemy handles the translation between Python objects and the specific database's SQL dialect.

### SQLite (Default)

Subnet Whisperer uses SQLAlchemy with SQLite by default. The setup script automatically creates the SQLite database at `instance/subnet_whisperer.db` when you first run the application. No additional database software installation is required for the default SQLite configuration.

### PostgreSQL (Optional)

To use PostgreSQL instead of SQLite:

1. Install PostgreSQL on your system:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install -y postgresql postgresql-contrib
   
   # On CentOS/RHEL
   sudo yum install -y postgresql postgresql-server
   sudo postgresql-setup initdb
   sudo systemctl start postgresql
   ```

2. Create a database and user:
   ```bash
   sudo -u postgres psql
   postgres=# CREATE DATABASE subnet_whisperer;
   postgres=# CREATE USER myuser WITH ENCRYPTED PASSWORD 'mypassword';
   postgres=# GRANT ALL PRIVILEGES ON DATABASE subnet_whisperer TO myuser;
   postgres=# \q
   ```

3. Set the `DATABASE_URL` environment variable:
   ```bash
   export DATABASE_URL="postgresql://myuser:mypassword@localhost/subnet_whisperer"
   ```

4. Run the setup script to migrate the database:
   ```bash
   ./setup.sh
   ```

Note: The setup script will automatically install Python packages including `psycopg2-binary`, which is required for PostgreSQL connectivity.

## Usage Guide

### 1. User Management

Admin users can manage accounts from the user dropdown menu in the top-right corner:

1. **Create users**: Click "User Management" then "Create User" to add new accounts
2. **Assign roles**: Check "Admin privileges" when creating a user to grant admin access
3. **Reset passwords**: Click "Reset Password" next to any user to set a new password
4. **Delete users**: Remove user accounts (admins cannot delete their own account)
5. **Change your password**: Select "Change Password" from the user dropdown menu

All routes require authentication. Unauthenticated users are redirected to the login page.

### 2. Scanning Subnets

1. Navigate to the "Scan" page
2. Enter subnets in CIDR notation (e.g., 192.168.1.0/24) or IP ranges (e.g., 192.168.1.1-192.168.1.10)
3. Enter SSH credentials (username and password/private key)
4. Choose a command template or enter custom commands
5. Set scan options (server information collection level, concurrency)
6. Click "Start Scan"

### 3. Server Information Collection

The application offers two levels of server information collection:

- **Basic Server Information**: Collects essential system details (hostname, OS, CPU, memory, disk)
- **Detailed Server Profile**: Collects comprehensive information including:
  - Network cards and interfaces
  - IP configurations
  - DNS settings
  - Running services
  - Network connections
  - Default gateways
  - Virtualization information

### 4. Command Templates

Create reusable command templates for common operations:

1. Navigate to the "Templates" page
2. Enter a name and description for your template
3. Add the commands you want to execute
4. Save the template

### 5. Viewing Results

1. Navigate to the "Results" page
2. Select a scan session to view
3. Explore scan results with filtering options
4. View detailed information for each scanned host
5. Export results in CSV, JSON, or PDF format

### 6. Managing Credential Sets

1. Navigate to the "Credentials" page
2. Click "Add New Credential Set" to create a new set of credentials
3. Enter a username and choose authentication type (password or SSH key)
4. Enter password or paste SSH private key (will be securely encrypted)
5. Optionally enter a sudo password for elevated commands
6. Set a priority level for auto-try functionality (higher number = higher priority)
7. Add a description to help identify the credential set
8. View, edit, or delete credential sets as needed

### 7. Setting Up Scheduled Scans

1. Navigate to the "Schedules" page
2. Click "New Schedule" to create a scheduled scan
3. Configure scan parameters (subnets, credentials, commands)
4. Set the schedule frequency (hourly, daily, weekly, monthly, or custom)
5. Define start and end dates (optional)
6. Activate or deactivate schedules as needed

## Security Features

- **User Authentication**: All routes require login; sessions managed via Flask-Login with bcrypt password hashing
- **Role-Based Access**: Admin users can manage accounts; regular users can only change their own password
- **CSRF Protection**: All forms and AJAX requests are protected against cross-site request forgery
- **SSH Host Key Verification**: Unknown SSH host keys trigger warnings instead of being silently accepted
- **Credential Encryption**: SSH credentials are secured using Fernet symmetric encryption
- **Command Sanitization**: Blocks dangerous or destructive commands before they execute
- **Sensitive Data Masking**: Automatically masks passwords, keys, and other sensitive information in logs
- **Key Derivation**: Encryption keys are derived from application secrets or environment variables
- **Secure Storage**: Passwords, SSH keys, and sudo passwords are stored with proper encryption
- **Multiple Credential Sets**: Create and manage multiple credential sets with different priority levels
- **Auto-Try Functionality**: System can automatically try multiple credential sets in order of priority
- **Persistent Session Secret**: Session secret is persisted to disk, preventing session invalidation across restarts

### Encryption Configuration

For optimal security, set an `ENCRYPTION_KEY` environment variable:
```bash
export ENCRYPTION_KEY="your-secure-encryption-key"
```

Alternatively, set a `FLASK_SECRET_KEY` or `SECRET_KEY` environment variable:
```bash
export FLASK_SECRET_KEY="your-secure-application-secret"
```

If neither is provided, a temporary key will be generated, but credentials will need to be re-entered after application restart.

## Security Features

### Command Sanitization
The application implements robust command sanitization to prevent dangerous commands from being executed on remote systems:

- Block destructive commands (rm -rf, format operations, etc.)
- Prevent shell command chaining and injection
- Restrict commands targeting sensitive system files
- Block execution of downloaded content
- Prevent fork bombs and other denial-of-service attacks
- Require explicit approval for privileged operations
- Log all security-related decisions for audit purposes

All sanitization patterns are defined in the `security_utils.py` file, including:
- `DANGEROUS_COMMANDS`: List of specific dangerous commands that are blocked entirely
- `DANGEROUS_PATTERNS`: Regex patterns that match potentially dangerous command structures
- `RESTRICTED_COMMANDS`: Commands that require extra scrutiny or admin approval
- `SENSITIVE_DATA_PATTERNS`: Patterns to identify and mask sensitive information in logs and outputs

#### Shell Operator Restrictions

As a deliberate security-over-convenience tradeoff, Subnet Whisperer **blocks all commands** containing shell operators such as `|` (pipe), `>` (redirect), `;` (semicolon), `&&` (and), and `||` (or). This prevents shell injection attacks where a malicious or accidental command could chain destructive operations onto an otherwise safe command.

**Examples of commands that will be blocked:**

| Command | Reason |
|---------|--------|
| `ps aux \| grep nginx` | Contains pipe (`\|`) |
| `echo "hello" > /tmp/test.txt` | Contains redirect (`>`) |
| `cd /var/log; cat syslog` | Contains semicolon (`;`) |
| `mkdir /tmp/backup && cp file /tmp/backup/` | Contains `&&` |
| `cat /etc/hostname \|\| echo "unknown"` | Contains `\|\|` |
| `df -h \| grep /dev` | Contains pipe (`\|`) |
| `dmesg \| tail -50` | Contains pipe (`\|`) |

**Examples of commands that will be allowed:**

| Command | Description |
|---------|-------------|
| `hostname -f` | Simple single command |
| `uname -a` | System information |
| `df -h` | Disk usage |
| `free -m` | Memory usage |
| `uptime` | System uptime |
| `ls -la /var/log/` | Directory listing |
| `cat /etc/os-release` | OS information |
| `sudo apt list --installed` | List packages (sudo is allowed) |

**Workaround for complex commands:** If you need to run commands that require pipes or redirection, create a shell script on the target server and execute it as a single command instead. For example:

1. Create a script on the target server:
   ```bash
   echo '#!/bin/bash' > /usr/local/bin/check-nginx.sh
   echo 'ps aux | grep nginx | grep -v grep' >> /usr/local/bin/check-nginx.sh
   chmod +x /usr/local/bin/check-nginx.sh
   ```

2. Then use Subnet Whisperer to run:
   ```
   /usr/local/bin/check-nginx.sh
   ```

### Credential Protection
- All sensitive credentials are strongly encrypted using Fernet symmetric encryption
- Private keys and passwords are never stored in plaintext
- Sudo passwords are securely encrypted in the database
- Multiple key derivation options for maximum security:
  - Direct encryption key from environment variables
  - Derived key from application secrets using PBKDF2
  - Fall back to secure key storage on disk with proper permissions
- Automatic masking of sensitive information in logs and outputs

## Security Considerations

- Sensitive SSH credentials are encrypted in the database using Fernet symmetric encryption
- SSH private keys are stored encrypted and only decrypted in memory when needed
- Command validation blocks potentially dangerous operations before they reach remote systems
- Sensitive information is automatically masked in logs and command outputs
- Consider using key-based authentication instead of passwords for added security
- Ensure you have permission to scan and connect to target hosts
- **Important**: While credentials are encrypted and command outputs are filtered for sensitive data, server information and non-sensitive command outputs are stored in the database without encryption. Be cautious about what commands you run if they might return sensitive information.

## Troubleshooting

- **SSH Connection Issues**: Verify connectivity, credentials, and firewall settings
- **Slow Scanning**: Adjust concurrency based on your network and target environment
- **Command Execution Failures**: Check sudo permissions on target hosts
- **Encryption Issues**: If you get decryption errors after upgrading, you may need to re-enter credentials

## Copyright and License

**Copyright © 2025 Meletis Belsis**

This project is free for any use as long as you include the original copyright statement and a link to the author's GitHub account.

### Disclaimer

**USE AT YOUR OWN RISK**: This application implements security best practices including credential encryption, but may still contain bugs or security vulnerabilities. By using this software, you assume all associated risks.

## Screenshots

### Modern UI Design

#### Dashboard View
![Dashboard View](attached_assets/whisperer1.png)

#### Subnet Scanner Interface
![Subnet Scanner Interface](attached_assets/whisperer2.png)

#### Scheduled Scans Manager
![Scheduled Scans Manager](attached_assets/whisperer3.png)

