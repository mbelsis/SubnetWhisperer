# Subnet Whisperer

![Subnet Whisperer Logo](generated-icon.png)

A powerful web-based tool for scanning subnets, executing commands via SSH, and analyzing results with multi-threading support.

## Support This Project

If you enjoy using this app, why not [![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://buymeacoffee.com/mbelsis)

## Features

- **Subnet Scanning**: Scan multiple IP addresses or subnets in parallel
- **SSH Connection**: Connect to remote hosts using password or key-based authentication
- **Command Execution**: Run custom commands or use predefined templates
- **Server Profiling**: Collect basic or detailed information about remote servers
- **Result Analysis**: View and filter scan results with charts and statistics
- **Export Capabilities**: Export results in CSV, JSON, or PDF format
- **Scheduled Scans**: Set up recurring scans to automate subnet monitoring
- **Multi-threading**: Perform parallel scanning for efficient operations

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
│   │   └── custom.css
│   └── js/
│       ├── main.js            # Common utility functions
│       ├── results.js         # Results page functionality
│       └── scan.js            # Scan page functionality
├── templates/                 # HTML templates
│   ├── 404.html
│   ├── 500.html
│   ├── base.html             # Base template with common elements
│   ├── index.html            # Home page
│   ├── results.html          # Results viewing page
│   ├── scan.html             # Scan configuration page
│   ├── settings.html         # Application settings
│   └── templates.html        # Command templates management
├── app.py                    # Flask application and routes
├── forms.py                  # Form definitions
├── main.py                   # Application entry point
├── migration.py              # Database migration script
├── models.py                 # Database models
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

Steps:
1. Clone the repository
2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

### Option 2: Manual Installation

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install flask flask-login flask-sqlalchemy flask-wtf gunicorn matplotlib pandas paramiko psycopg2-binary sqlalchemy wtforms email-validator
   ```
4. Create the instance directory:
   ```bash
   mkdir -p instance
   ```
5. Initialize the database:
   ```bash
   python migration.py
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```
6. Create logs directory:
   ```bash
   mkdir -p logs
   ```

## Running the Application

```bash
python main.py
```

The application will be available at http://localhost:5000

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

### 1. Scanning Subnets

1. Navigate to the "Scan" page
2. Enter subnets in CIDR notation (e.g., 192.168.1.0/24) or IP ranges (e.g., 192.168.1.1-192.168.1.10)
3. Enter SSH credentials (username and password/private key)
4. Choose a command template or enter custom commands
5. Set scan options (server information collection level, concurrency)
6. Click "Start Scan"

### 2. Server Information Collection

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

### 3. Command Templates

Create reusable command templates for common operations:

1. Navigate to the "Templates" page
2. Enter a name and description for your template
3. Add the commands you want to execute
4. Save the template

### 4. Viewing Results

1. Navigate to the "Results" page
2. Select a scan session to view
3. Explore scan results with filtering options
4. View detailed information for each scanned host
5. Export results in CSV, JSON, or PDF format

### 5. Setting Up Scheduled Scans

1. Navigate to the "Schedules" page
2. Click "New Schedule" to create a scheduled scan
3. Configure scan parameters (subnets, credentials, commands)
4. Set the schedule frequency (hourly, daily, weekly, monthly, or custom)
5. Define start and end dates (optional)
6. Activate or deactivate schedules as needed

## Security Considerations

- SSH credentials are transmitted securely but are not stored in the database
- Private keys are only used in memory and not persisted
- Consider using key-based authentication instead of passwords
- Ensure you have permission to scan and connect to target hosts
- **Important**: Server information and command outputs are stored in the database without encryption. Do not store sensitive information in the database.

## Troubleshooting

- **SSH Connection Issues**: Verify connectivity, credentials, and firewall settings
- **Slow Scanning**: Adjust concurrency based on your network and target environment
- **Command Execution Failures**: Check sudo permissions on target hosts

## Copyright and License

**Copyright © 2025 Meletis Belsis**

This project is free for any use as long as you include the original copyright statement and a link to the author's GitHub account.

### Disclaimer

**USE AT YOUR OWN RISK**: This application is a work in progress. Data stored in the database is not encrypted. The application may contain bugs or security vulnerabilities. By using this software, you assume all associated risks.

## Screenshots

### Application Screenshots

#### Home Screen
![Home Screen](attached_assets/mainscreen1.png)

#### Subnet Scanner
![Subnet Scanner](attached_assets/scanscreen.png)

#### Results Screen
![Results Screen](attached_assets/resultsscreen.png)

#### Scheduled Scans
![Scheduled Scans](attached_assets/scheduler.png)

### New UI Design

#### Dashboard View
![Dashboard View](attached_assets/whisperer1.png)

#### Subnet Scanner Interface
![Subnet Scanner Interface](attached_assets/whisperer2.png)

#### Scheduled Scans Manager
![Scheduled Scans Manager](attached_assets/whisperer3.png)