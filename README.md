# Subnet Whisperer

![Subnet Whisperer Logo](generated-icon.png)

A powerful web-based tool for scanning subnets, executing commands via SSH, and analyzing results with multi-threading support.

## Features

- **Subnet Scanning**: Scan multiple IP addresses or subnets in parallel
- **SSH Connection**: Connect to remote hosts using password or key-based authentication
- **Command Execution**: Run custom commands or use predefined templates
- **Server Profiling**: Collect basic or detailed information about remote servers
- **Result Analysis**: View and filter scan results with charts and statistics
- **Export Capabilities**: Export results in CSV or JSON format
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

### Option 1: Using the Setup Script

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
   pip install -r requirements.txt
   ```
4. Initialize the database:
   ```bash
   python migration.py
   ```

## Running the Application

```bash
python main.py
```

The application will be available at http://localhost:5000

## Database Setup

Subnet Whisperer uses SQLAlchemy with SQLite by default. The database file will be created automatically at `instance/subnet_whisperer.db` when you first run the application.

### Using a Different Database

To use a different database (e.g., PostgreSQL), set the `DATABASE_URL` environment variable:

```bash
export DATABASE_URL="postgresql://username:password@localhost/subnet_whisperer"
```

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
5. Export results in CSV or JSON format

## Security Considerations

- SSH credentials are transmitted securely but are not stored in the database
- Private keys are only used in memory and not persisted
- Consider using key-based authentication instead of passwords
- Ensure you have permission to scan and connect to target hosts

## Troubleshooting

- **SSH Connection Issues**: Verify connectivity, credentials, and firewall settings
- **Slow Scanning**: Adjust concurrency based on your network and target environment
- **Command Execution Failures**: Check sudo permissions on target hosts

## License

This project is licensed under the MIT License - see the LICENSE file for details.