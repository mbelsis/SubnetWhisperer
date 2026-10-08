# Subnet Whisperer

![Subnet Whisperer Logo](generated-icon.png)

A web-based tool for scanning subnets, running commands over SSH and analysing the results, with multi-threaded scanning, encrypted credential storage, scheduled scans and server profiling.

## Features

- **User Authentication**: login-protected interface with admin and non-admin roles
- **Subnet Scanning**: scan IPv4 and IPv6 addresses, CIDR subnets and ranges in parallel
- **SSH Connection**: password or private-key authentication, on a configurable port
- **Command Execution**: run custom commands or predefined templates, with a best-effort command filter
- **Server Profiling**: collect basic or detailed information about remote servers
- **Result Analysis**: view and filter scan results with charts and statistics
- **Export**: CSV (protected against spreadsheet formula injection), JSON or PDF
- **Scheduled Scans**: recurring scans run by a background scheduler
- **Encrypted Credential Storage**: SSH passwords, keys and sudo passwords are encrypted with Fernet
- **Multiple Credential Sets**: saved credential sets are tried in priority order
- **Customizable Theme**: dark and light mode

## System Requirements

- Python 3.11 or newer
- SQLite (default) or PostgreSQL
- Basic understanding of SSH and network operations

## Project Structure

```
SubnetWhisperer/
├── app.py                    # Flask application and routes
├── main.py                   # Development entry point (python3 main.py)
├── models.py                 # Database models (User, ScanSession, ScheduledScan, ...)
├── forms.py                  # Flask-WTF form definitions
├── encryption_utils.py       # Fernet key management and credential encryption
├── security_utils.py         # Command filter and sensitive-data masking
├── ssh_utils.py              # SSH connections, host-key policy, scan workers
├── subnet_utils.py           # IPv4/IPv6 subnet, range and CSV parsing
├── scheduler.py              # Background scheduler for recurring scans
├── run_migrations.py         # Creates/updates the schema explicitly (non-zero exit on failure)
├── migrations/               # Schema sync (adds missing tables and columns)
├── static/
│   ├── css/                  # Custom styling and dark/light theme
│   └── js/                   # Page scripts (common helpers, scan, results, theme)
├── templates/                # Jinja2 HTML templates
├── tests/                    # Unit smoke tests and Docker SSH integration tests
│   ├── test_app.py
│   ├── test_docker_integration.py
│   ├── run_docker_integration.py
│   ├── docker-compose.integration.yml
│   ├── docker/               # SSH target images and test-only keys
│   └── README.md
├── instance/                 # Runtime data, created on first start, NOT in git
│   ├── subnet_whisperer.db   #   SQLite database (default)
│   ├── .encryption_key       #   Fernet key (if ENCRYPTION_KEY is not set): back it up
│   ├── .secret_key           #   Session secret (if SESSION_SECRET is not set)
│   ├── known_hosts           #   SSH host keys recorded by the TOFU policy
│   └── initial_admin_password  # First admin password (only if ADMIN_PASSWORD was unset)
├── logs/                     # Application logs
├── Dockerfile                # Multi-stage image, runs gunicorn
├── docker-compose.yml        # SQLite and PostgreSQL deployments
├── docker-start.sh           # Compose wrapper (SQLite or postgres)
├── .dockerignore
├── Makefile                  # Docker shortcuts (run `make` for help)
├── setup.sh                  # Local installation script
├── .env.example              # Documented configuration variables
├── pyproject.toml            # Project metadata and dependencies
├── uv.lock                   # Pinned dependency versions
├── TESTING.md                # Testing guide
└── .replit, replit.nix       # Replit configuration
```

## Installation

### Prerequisites

- Python 3.11 or newer, with pip
- Windows only: Microsoft Visual C++ 14.0 or newer may be needed for some dependencies

### Option 1: Setup Script (Linux and macOS)

```bash
chmod +x setup.sh
./setup.sh
```

The script:
- checks for Python 3.11+ (`python3`, override with `PYTHON=/path/to/python`)
- installs the dependencies (from `uv.lock` if `uv` is installed, otherwise from `pyproject.toml`)
- creates `instance/` and `logs/`
- creates `.env` from `.env.example` if it doesn't exist and appends a `SESSION_SECRET` if one is missing. An existing `.env` is never overwritten, and existing values are never changed
- creates or updates the database schema (`run_migrations.py`) and stops with an error if that fails

See [First Login](#first-login) for the admin password.

### Option 2: Manual Installation

```bash
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
# with uv (exact versions from uv.lock):
uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt && pip install -r requirements.txt
# or, without uv, install the dependencies listed in pyproject.toml:
pip install "email-validator>=2.2.0" "flask-wtf>=1.2.2" "flask>=3.1.0" "flask-sqlalchemy>=3.1.1" \
    "gunicorn>=23.0.0" "pandas>=2.2.3" "paramiko>=3.5.1" "psycopg2-binary>=2.9.10" "wtforms>=3.2.1" \
    "flask-login>=0.6.3" "matplotlib>=3.10.1" "sqlalchemy>=2.0.40" "bcrypt>=4.3.0" "cryptography>=44.0.2"

mkdir -p instance logs
python3 run_migrations.py   # optional: the schema is also synced when the app starts
```

## Running the Application

### Development server

```bash
python3 main.py
```

`main.py` starts Flask's development server (the database schema is created or updated automatically when the app is imported) on `FLASK_HOST` (default `127.0.0.1`) and `PORT` (default `5000`), so it is only reachable from the local machine by default. Debug mode (the Werkzeug debugger) is enabled only with `FLASK_DEBUG=true`. Never enable it on an address other people can reach: the debugger allows remote code execution.

The app does not read `.env` by itself. To use it outside Docker, export it first:

```bash
set -a; . ./.env; set +a
python3 main.py
```

### Production (gunicorn)

```bash
gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 main:app
```

Use one worker per instance: each process starts its own scheduler (see [Scheduled Scans](#scheduled-scans)). Put a TLS-terminating reverse proxy in front and set `SESSION_COOKIE_SECURE=true`.

### First Login

On first start (when the database has no users) an `admin` account is created:

- The password is the value of `ADMIN_PASSWORD`, if it is set.
- Otherwise a random password is generated. It is logged once at WARNING level and written to `instance/initial_admin_password` (mode 600). Delete that file after you have logged in.

Either way, you must change the password at first login: until you do, every page redirects to **Change Password**. Passwords must be at least 8 characters.

## Docker Deployment

### Docker Compose (recommended)

```bash
cp .env.example .env      # then edit .env
./docker-start.sh         # SQLite
./docker-start.sh postgres  # PostgreSQL (POSTGRES_PASSWORD must be set)
```

Or with Make (run `make` on its own to list the targets):

```bash
make build          # Build the image
make run            # Run with SQLite
make run-postgres   # Run with PostgreSQL (needs POSTGRES_PASSWORD)
make stop           # Stop all containers
make clean          # Remove this project's containers, networks and volumes (including the PostgreSQL data volume)
make prune          # Host-wide 'docker system prune', asks for confirmation first
```

The Makefile uses `docker compose`. For the legacy binary run `make COMPOSE=docker-compose <target>`.

Compose reads `.env` from the project folder and passes these variables to the app: `ENCRYPTION_KEY`, `FLASK_SECRET_KEY` (legacy, no default), `SESSION_SECRET`, `ADMIN_PASSWORD`, `SESSION_COOKIE_SECURE`, `COMMAND_SANITIZATION`, `SSH_HOST_KEY_POLICY`, `MAX_SCAN_IPS`, `MAX_CONCURRENCY`, `START_SCHEDULER` and `DATABASE_URL`. Empty values count as unset.

- **Encryption key**: if `ENCRYPTION_KEY` is not set, the app creates `instance/.encryption_key` in the bind-mounted `./instance` folder on first start. Back it up.
- **PostgreSQL**: the `postgres` profile takes `POSTGRES_USER` (default `postgres`), `POSTGRES_PASSWORD` (required) and `POSTGRES_DB` (default `subnet_whisperer`) and builds `DATABASE_URL` from them. The database port is **not** published on the host; only the app container can reach it. Use a password without URL-special characters (`@ : / ? #`).

The app is available at http://localhost:5000.

### Docker directly

```bash
docker build -t subnet-whisperer .
docker run -p 5000:5000 \
  -e ENCRYPTION_KEY="<fernet key>" \
  -e DATABASE_URL="postgresql://user:password@host/dbname" \
  -v "$(pwd)/instance:/app/instance" \
  -v "$(pwd)/logs:/app/logs" \
  subnet-whisperer
```

### Docker Image

- Multi-stage build on `python:3.11-slim`. Compilers and `-dev` headers are used only in the build stage; the runtime image contains the virtualenv, `openssh-client` and the app code.
- Dependencies are installed at the exact versions pinned in `uv.lock`.
- `tests/` (including its test-only SSH key), `instance/`, `.env` and docs are excluded by `.dockerignore`.
- Runs as the non-root user `appuser` (uid 1000) with gunicorn on `0.0.0.0:5000`, 1 worker and 4 threads, without `--reload`.

### Persistent Storage

- `instance/` (bind mount): SQLite database, `.encryption_key`, `.secret_key`, `known_hosts`, `initial_admin_password`
- `logs/` (bind mount): application logs
- PostgreSQL data: the named volume `postgres_data`

On Linux, the container user (uid 1000) must be able to write to `./instance` and `./logs`. If your host user has a different uid, run `sudo chown -R 1000:1000 instance logs`.

## Configuration

All settings are environment variables. [.env.example](.env.example) documents each one.

| Variable | Default | Purpose |
|---|---|---|
| `ENCRYPTION_KEY` | unset | Fernet key for stored credentials (see [Encryption Key](#encryption-key)) |
| `FLASK_SECRET_KEY` / `SECRET_KEY` | unset | Legacy encryption-key derivation only |
| `SESSION_SECRET` | `instance/.secret_key` | Flask session signing secret |
| `ADMIN_PASSWORD` | random | First admin password (first start only) |
| `DATABASE_URL` | `sqlite:///instance/subnet_whisperer.db` | SQLAlchemy database URL |
| `FLASK_DEBUG` | `false` | Werkzeug debugger (`main.py` only) |
| `FLASK_HOST` | `127.0.0.1` | Bind address (`main.py` only) |
| `PORT` | `5000` | Port (`main.py` only) |
| `SESSION_COOKIE_SECURE` | `false` | Send the session cookie over HTTPS only |
| `COMMAND_SANITIZATION` | `enabled` | Command filter mode (`enabled` or `disabled`) |
| `SSH_HOST_KEY_POLICY` | `tofu` | `tofu`, `reject` or `warn` |
| `SSH_KNOWN_HOSTS_FILE` | `instance/known_hosts` | Known-hosts file used by the app |
| `SSH_COMMAND_TIMEOUT` | `60` | Per-command timeout in seconds |
| `SSH_CONNECT_TIMEOUT` | `10` | SSH connect, banner and auth timeout in seconds |
| `SSH_MAX_OUTPUT_BYTES` | `1048576` | Output kept per stream per command (truncated beyond this) |
| `MAX_SCAN_IPS` | `65536` | Maximum IP addresses per scan |
| `MAX_CONCURRENCY` | `100` | Maximum concurrent connections per scan (minimum 1) |
| `START_SCHEDULER` | `true` | Set to `false` to disable the background scheduler |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | `postgres`, required, `subnet_whisperer` | docker compose `postgres` profile |

## Database Setup

Subnet Whisperer uses SQLAlchemy, so the same code runs on SQLite (default, a file in `instance/`) or PostgreSQL.

To use your own PostgreSQL server:

1. Create a database and user:
   ```bash
   sudo -u postgres psql
   postgres=# CREATE DATABASE subnet_whisperer;
   postgres=# CREATE USER myuser WITH ENCRYPTED PASSWORD 'mypassword';
   postgres=# GRANT ALL PRIVILEGES ON DATABASE subnet_whisperer TO myuser;
   postgres=# \q
   ```
2. Set `DATABASE_URL`:
   ```bash
   export DATABASE_URL="postgresql://myuser:mypassword@localhost/subnet_whisperer"
   ```
3. Run `./setup.sh` (or `python3 run_migrations.py`). The schema is also created or updated automatically when the app starts.

## Usage Guide

### User Management (admin)

From the user menu in the top-right corner, admins can create users (optionally with admin rights), reset passwords and delete users (but not their own account). Every user can change their own password. All pages require login.

### Scanning Subnets

1. Open **Scan**.
2. Enter targets, one per line or comma-separated: single addresses, CIDR subnets (`192.168.1.0/24`, `2001:db8::/120`) or ranges (`192.168.1.1-192.168.1.10`, `2001:db8::1-2001:db8::20`). IPv4 and IPv6 are both supported. Addresses are deduplicated and sorted, and invalid entries are reported. You can also import a CSV file.
3. Enter the SSH credentials (username plus password or private key) and the port, or (admins) choose saved credential sets.
4. Choose a command template or enter custom commands.
5. Choose the server-information level and the concurrency, then click **Start Scan**.

A single scan can include at most `MAX_SCAN_IPS` addresses (default 65536), and its concurrency is capped at `MAX_CONCURRENCY` (default 100, minimum 1).

### Server Information Collection

- **Basic**: hostname, OS, CPU, memory, disk
- **Detailed**: also network interfaces, IP configuration, DNS settings, running services, network connections, default gateways and virtualization

### Command Templates

Everyone can list templates and use them in scans. Admins can create, edit and delete them on the **Templates** page. Template names must be unique.

### Viewing Results

Open **Results**, pick a scan session, filter the per-host results and open host details. Export as CSV, JSON or PDF. Times are stored in UTC and shown in your browser's local time. Admins can delete scans.

### Managing Credential Sets (admin)

On **Credentials**, admins can add, edit and delete credential sets: a username, password or SSH private key (encrypted at rest), an optional sudo password, a priority (higher is tried first) and a description. When a scan uses several credential sets, each host is tried with them in priority order.

### Scheduled Scans

Admins manage schedules on **Schedules**: targets, credentials (manual or a saved credential set), port, sudo password, commands, frequency (hourly, daily, weekly, monthly or custom), and optional start and end dates. **Start and end times are entered and stored in UTC.** A schedule whose end date has passed cannot be activated.

The scheduler runs in the background in the web process. It starts when the app is imported unless `START_SCHEDULER=false`, and it checks for due schedules every 60 seconds. Each run is claimed atomically in the database, so even if several processes run a scheduler, a schedule is not run twice. The default single-worker gunicorn setup is still recommended.

## Security

Subnet Whisperer stores SSH credentials and runs commands on remote hosts. Run it on a trusted network, behind TLS, and give admin rights only to people who should be able to use every stored credential.

### Authentication and Roles

- All pages require login (Flask-Login, bcrypt password hashes, minimum length 8).
- The first admin's password comes from `ADMIN_PASSWORD` or is generated (see [First Login](#first-login)). A password change is forced at first login.
- **Admins** can: manage users; view and manage credential sets (`/credentials` and the credential API); use saved credential sets in scans; create, edit, activate and delete schedules; create, edit and delete command templates; delete scans.
- **Non-admins** can: run scans with manually entered credentials; view results and exports; list templates and use them in scans; change their own password.
- CSRF protection covers all forms and AJAX requests. Tokens last as long as the session.
- Logout is a POST request with a CSRF token. Session cookies are `SameSite=Lax`, and `Secure` when `SESSION_COOKIE_SECURE=true`.
- The session is signed with `SESSION_SECRET`, or with a secret generated once and stored in `instance/.secret_key`.

### Encryption Key

SSH passwords, private keys and sudo passwords are encrypted with Fernet. The key is chosen in this order:

1. **`ENCRYPTION_KEY`**. It must be a valid Fernet key; if it isn't, the app refuses to start with a clear error. Generate one with:
   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
2. **`instance/.encryption_key`**, if the file exists.
3. **Legacy**: a key derived (PBKDF2) from `FLASK_SECRET_KEY` or `SECRET_KEY`. A warning is logged. Use this only to keep reading credentials from an old install.
4. Otherwise a new key is generated and saved to `instance/.encryption_key` with mode 600.

**Keep and back up the key** (the `ENCRYPTION_KEY` value or `instance/.encryption_key`). If it is lost or changes, stored credentials can't be decrypted: decryption fails with an error and the credentials must be re-entered. Never commit the key or the `instance/` folder.

Server information and command output are stored **unencrypted** (after masking), so be careful with commands that print secrets.

### SSH Host Key Verification

Set with `SSH_HOST_KEY_POLICY`:

- **`tofu`** (default): trust on first use. The key of a host seen for the first time is recorded in `SSH_KNOWN_HOSTS_FILE` (default `instance/known_hosts`). If a known host later presents a different key, the connection is **rejected**. If a host's key legitimately changes, remove its line from that file.
- **`reject`**: only connect to hosts already listed in the system known_hosts or the app's known_hosts file.
- **`warn`**: legacy behavior. Any key is accepted and nothing is recorded, so there is no protection against man-in-the-middle attacks.

### Output and Log Masking

Passwords, private keys (including PKCS#8 and encrypted keys), tokens and similar values are masked in command output before it is stored or shown, and in the commands and messages written to the logs. The sudo password is masked wherever it appears. Masking is pattern-based, so treat it as a safety net, not a guarantee.

### Command Filtering

The command filter is a **best-effort guardrail against mistakes, not a security boundary**. Anyone who can run arbitrary commands over SSH with a set of credentials can do whatever those credentials allow, and a determined user can find commands the filter doesn't recognise. Control access with roles and with the permissions of the remote accounts.

Commands are tokenized like a shell (shlex) and checked before they are sent. A rejected command is simply not run; the result shows it as blocked. There is no approval workflow.

**Always blocked** (in every mode):

- `rm` recursive deletes of `/`, `/*` or `~`, in any flag order (`-rf`, `-fr`, `-r -f`, `--recursive --force`, `--no-preserve-root`)
- `find / ... -delete`
- `mkfs` and its variants (`mkfs.ext4`, ...)
- `dd`, `shred` or `wipefs` writing to block devices (`/dev/sd*`, `/dev/hd*`, `/dev/nvme*`, `/dev/vd*`, `/dev/xvd*`, `/dev/mmcblk*`)
- fork bombs
- `curl` or `wget` piped into `sh` or `bash`
- `shutdown`, `reboot`, `halt`, `poweroff`, `init 0`/`init 6`, `telinit 0`/`telinit 6` when used as commands (a word such as `halting-problem` is fine)
- `sudo -i`, `sudo -s`, `sudo su`
- access to `/etc/shadow` (`cat /etc/passwd` is allowed)

These checks also apply inside shell wrappers such as `bash -c "..."` or `sudo sh -c "..."`. Interpreters (`python -c`, `perl -e`, ...) are not inspected.

**Also blocked when `COMMAND_SANITIZATION=enabled`** (the default):

- shell operators and substitutions: `;`, `&&`, `||`, a single `&`, `|`, `>`, `<`, backticks, `$(`, `${` and newlines
- restricted commands, matched on the command name (after any `sudo`), for example `systemctl`, `chmod`, `useradd` and the rest of `RESTRICTED_COMMANDS` in `security_utils.py`. So `systemctl status nginx` is rejected in enabled mode.

With `COMMAND_SANITIZATION=disabled`, pipes, redirects, chaining and restricted commands are allowed; only the always-blocked list applies.

Examples in enabled mode:

| Command | Result |
|---|---|
| `uname -a`, `df -h`, `free -m`, `uptime`, `ls -la /var/log/` | allowed |
| `cat /etc/os-release`, `cat /etc/passwd` | allowed |
| `sudo apt list --installed` | allowed |
| `ps aux \| grep nginx` | blocked (pipe) |
| `cd /var/log; cat syslog` | blocked (`;`) |
| `echo hi > /tmp/x` | blocked (redirect) |
| `echo $(id)` | blocked (command substitution) |
| `systemctl status nginx` | blocked (restricted command) |
| `rm -fr /`, `sudo reboot` | blocked in every mode |

To run pipelines while keeping the filter enabled, put them in a script on the target and run the script as a single command, or set `COMMAND_SANITIZATION=disabled`.

## Upgrading from Earlier Versions

- **`instance/` is no longer tracked in git.** Pulling the change that untracked it deletes `instance/.encryption_key` and `instance/subnet_whisperer.db` from your working copy. **Back up `instance/` before you pull** (`cp -a instance instance.backup`) and restore it afterwards. Keep your existing `instance/.encryption_key`: it is the key your stored credentials are encrypted with.
- **The committed key is public.** The `.encryption_key` that used to be in the repository is known to anyone with access to it. If your install used that file, rotate the SSH credentials you stored, then start with a new key (delete `instance/.encryption_key` and set a fresh `ENCRYPTION_KEY`, or let the app generate a new file) and re-enter the credentials.
- **docker-compose no longer sets `FLASK_SECRET_KEY`.** Old compose files defaulted it to `default_dev_key_please_change_in_production`, and the encryption key was derived from it. That key is public too. To read the old credentials once, either:
  - set `ENCRYPTION_KEY` to the legacy derived key:
    ```bash
    python3 -c "import base64,sys; from cryptography.hazmat.primitives import hashes; from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC; print(base64.urlsafe_b64encode(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'subnet_whisperer_secure_salt_v2', iterations=480000).derive(sys.argv[1].encode())).decode())" 'default_dev_key_please_change_in_production'
    ```
  - or set `FLASK_SECRET_KEY` to the old value and move `instance/.encryption_key` out of the way (the key file takes priority over `FLASK_SECRET_KEY`).

  Either way, plan to rotate the credentials and move to a fresh key, or simply re-enter them.
- **PostgreSQL in compose** now needs `POSTGRES_PASSWORD`, and port 5432 is no longer published. If your existing `postgres_data` volume was initialised with `postgres`/`postgres`, set `POSTGRES_PASSWORD=postgres` (or change the password inside the database first).
- **Python 3.11** is now required.
- **Schedules** are interpreted in UTC. Check the start and end times of existing schedules.

## Testing

See [TESTING.md](TESTING.md) and [tests/README.md](tests/README.md). Tests set `START_SCHEDULER=false`.

## Troubleshooting

- **SSH connection rejected with a host key error**: the host's key changed since it was first recorded (TOFU). Verify the change, then remove the host's line from `instance/known_hosts`.
- **App won't start, "invalid ENCRYPTION_KEY"**: the value isn't a Fernet key. Generate one as shown above, or unset it to use `instance/.encryption_key`.
- **Decryption errors**: the encryption key changed. Restore the old key, or re-enter the credentials.
- **Permission denied on `instance/` in Docker**: see [Persistent Storage](#persistent-storage).
- **"Too many IP addresses"**: split the scan, or raise `MAX_SCAN_IPS`.
- **Slow scans**: adjust concurrency for your network and targets.
- **Command failures with sudo**: check sudo permissions on the target hosts.

## Copyright and License

**Copyright © 2025 Meletis Belsis**

This project is free for any use as long as you include the original copyright statement and a link to the author's GitHub account.

### Disclaimer

**USE AT YOUR OWN RISK**: This application implements security best practices including credential encryption, but may still contain bugs or security vulnerabilities. By using this software, you assume all associated risks.

## Screenshots

#### Dashboard View
![Dashboard View](attached_assets/whisperer1.png)

#### Subnet Scanner Interface
![Subnet Scanner Interface](attached_assets/whisperer2.png)

#### Scheduled Scans Manager
![Scheduled Scans Manager](attached_assets/whisperer3.png)
