# Subnet Whisperer

![Subnet Whisperer Logo](generated-icon.png)

A web-based tool for scanning subnets, running commands over SSH and analysing the results, with multi-threaded scanning, encrypted credential storage, scheduled scans and server profiling.

## Features

- **User Authentication**: login-protected interface with admin and non-admin roles, login lockout after repeated failures, and per-user scan visibility (non-admins see only their own scans)
- **Subnet Scanning**: scan IPv4 and IPv6 addresses, CIDR subnets and ranges in parallel
- **SSH Connection**: password or private-key authentication (with or without a key passphrase), sudo with or without a password, on a configurable port
- **Command Execution**: run custom commands or predefined templates, with an optional command allowlist (only admin-approved template lines run) or a best-effort denylist filter
- **Server Profiling**: collect basic or detailed information about remote servers
- **Result Analysis**: view and filter scan results with charts and statistics
- **Export**: CSV (protected against spreadsheet formula injection), JSON or PDF
- **Scheduled Scans**: recurring scans run by a background scheduler
- **Encrypted Credential Storage**: SSH passwords, keys, key passphrases and sudo passwords are encrypted with Fernet
- **Multiple Credential Sets**: saved credential sets are tried in priority order, each optionally limited to the subnets it belongs to
- **Scan Scope**: optional list of authorised networks (`SCAN_ALLOWED_SUBNETS`); targets outside it are refused
- **Audit Log**: sign-ins, scans, exports and every configuration change, viewable by admins and written to the `audit` logger
- **Customizable Theme**: dark and light mode

## Quick Start

Pick one of the two ways below. Both give you the web app with a SQLite database stored in `instance/`.

### A. Docker (recommended)

Requires Docker with the Compose plugin.

```bash
git clone https://github.com/mbelsis/SubnetWhisperer.git
cd SubnetWhisperer
cp .env.example .env                 # optional settings; the defaults work
./docker-start.sh                    # or: make run   (builds the image on first run)
```

Open http://localhost:5000. On **macOS**, port 5000 is used by the AirPlay Receiver: add `HOST_PORT=5050` to `.env` and open http://localhost:5050 instead.

Get the first admin password (user `admin`):

```bash
cat instance/initial_admin_password
# or: docker compose logs web | grep "initial admin"
```

### B. Local Python install (Linux and macOS)

Requires Python 3.11 or newer (`python3 --version`; on macOS install it with `brew install python@3.12`).

```bash
git clone https://github.com/mbelsis/SubnetWhisperer.git
cd SubnetWhisperer
./setup.sh                           # or: PYTHON=python3.12 ./setup.sh
source .venv/bin/activate
set -a; . ./.env; set +a             # load your settings
python main.py                       # macOS: PORT=5050 python main.py
```

Open http://127.0.0.1:5000 (or the port you chose). The first admin password is printed by `setup.sh` and saved in `instance/initial_admin_password`.

### Then

1. Log in as `admin` with that password. You are asked to choose a new password (at least 8 characters); the `initial_admin_password` file is deleted automatically afterwards.
2. Follow the [Usage Guide](#usage-guide): add credentials, create a template, run a scan.

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
│   ├── docker/               # SSH target images (test key pair is generated at test time)
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
./setup.sh                      # uses python3
PYTHON=python3.12 ./setup.sh    # or choose the interpreter
```

The script:
- checks for Python 3.11+ and stops with a clear error on older versions
- uses the active virtualenv, or creates and uses `.venv/` (system and Homebrew Pythons refuse global `pip install`)
- installs the dependencies (exact versions from `uv.lock` if `uv` is installed, otherwise the ranges in `pyproject.toml`)
- creates `instance/` and `logs/`
- creates `.env` from `.env.example` if it doesn't exist and appends a `SESSION_SECRET` if one is missing. An existing `.env` is never overwritten, and existing values are never changed
- creates or updates the database schema (`run_migrations.py`), creates the first admin account, and stops with an error if anything fails

It is safe to run again, for example after pulling a new version.

### Option 2: Manual Installation

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
# with uv (exact versions from uv.lock):
uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt && pip install -r requirements.txt
# or, without uv, install the dependencies listed in pyproject.toml:
pip install "email-validator>=2.2.0" "flask-wtf>=1.2.2" "flask>=3.1.0" "flask-sqlalchemy>=3.1.1" \
    "gunicorn>=23.0.0" "pandas>=2.2.3" "paramiko>=3.5.1" "psycopg2-binary>=2.9.10" "wtforms>=3.2.1" \
    "flask-login>=0.6.3" "matplotlib>=3.10.1" "sqlalchemy>=2.0.40" "bcrypt>=4.3.0" "cryptography>=44.0.2"

mkdir -p instance logs
python run_migrations.py   # optional: the schema is also synced when the app starts
```

## Running the Application

### Development server

```bash
source .venv/bin/activate
python main.py
```

`main.py` starts Flask's development server (the database schema is created or updated automatically when the app is imported) on `FLASK_HOST` (default `127.0.0.1`) and `PORT` (default `5000`), so it is only reachable from the local machine by default. Debug mode (the Werkzeug debugger) is enabled only with `FLASK_DEBUG=true`. Never enable it on an address other people can reach: the debugger allows remote code execution.

The app does not read `.env` by itself. To use it outside Docker, export it first:

```bash
set -a; . ./.env; set +a
python main.py
```

If port 5000 is busy (on macOS it is used by the AirPlay Receiver), choose another: `PORT=5050 python main.py`.

### Production (gunicorn)

```bash
gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 main:app
```

Use one worker per instance: each process starts its own scheduler (see [Scheduled Scans](#scheduled-scans)). Put a TLS-terminating reverse proxy in front and set `SESSION_COOKIE_SECURE=true`.

### First Login

On first start (when the database has no users) an `admin` account is created:

- The password is the value of `ADMIN_PASSWORD`, if it is set when the database is first created.
- Otherwise a random password is generated. It is logged once at WARNING level and written to `instance/initial_admin_password` (mode 600):
  ```bash
  cat instance/initial_admin_password
  ```

Either way, you must change the password at first login: until you do, every page redirects to **Change Password**. Passwords must be at least 8 characters. Once an admin has changed the password, `instance/initial_admin_password` is deleted automatically.

Only a bcrypt hash of each user's password is stored, in the `users` table of the database. Lost the admin password? Another admin can reset it on **User Management**; if there is no other admin, stop the app, delete the database (`instance/subnet_whisperer.db`, which also deletes scans, templates, schedules and saved credentials), and start again to get a new first-run password.

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

Compose reads `.env` from the project folder and passes these variables to the app: `ENCRYPTION_KEY`, `FLASK_SECRET_KEY` (legacy, no default), `SESSION_SECRET`, `ADMIN_PASSWORD`, `SESSION_COOKIE_SECURE`, `COMMAND_SANITIZATION`, `SCAN_ALLOWED_SUBNETS`, `SSH_HOST_KEY_POLICY`, `MAX_SCAN_IPS`, `MAX_CONCURRENCY`, `LOGIN_MAX_FAILURES`, `LOGIN_IP_MAX_FAILURES`, `LOGIN_LOCKOUT_MINUTES`, `TRUST_PROXY_HOPS`, `START_SCHEDULER` and `DATABASE_URL`. Empty values count as unset.

- **Encryption key**: if `ENCRYPTION_KEY` is not set, the app creates `instance/.encryption_key` in the bind-mounted `./instance` folder on first start. Back it up.
- **PostgreSQL**: the `postgres` profile takes `POSTGRES_USER` (default `postgres`), `POSTGRES_PASSWORD` (required) and `POSTGRES_DB` (default `subnet_whisperer`) and builds `DATABASE_URL` from them. The database port is **not** published on the host; only the app container can reach it. Use a password without URL-special characters (`@ : / ? #`).

The app is available at http://localhost:5000, or on the port set with `HOST_PORT` in `.env` (for example `HOST_PORT=5050` on macOS, where port 5000 is used by the AirPlay Receiver). To follow the logs: `docker compose logs -f web`. To stop: `make stop` or `docker compose down`.

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

All settings are environment variables. [.env.example](.env.example) documents each one. The **Settings** page in the app shows the values the running instance is using (read-only).

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
| `HOST_PORT` | `5000` | Host port published by docker compose |
| `SESSION_COOKIE_SECURE` | `false` | Send the session cookie over HTTPS only |
| `COMMAND_SANITIZATION` | `enabled` | Command policy: `allowlist`, `enabled` or `disabled` (see [Command Filtering](#command-filtering)) |
| `SCAN_ALLOWED_SUBNETS` | unset (any) | Authorised scan scope: CIDRs/addresses scans and schedules may target |
| `LOGIN_MAX_FAILURES` | `5` | Failed logins per username and client address before a lockout |
| `LOGIN_IP_MAX_FAILURES` | `20` | Failed logins per client address (any username) before a lockout |
| `LOGIN_LOCKOUT_MINUTES` | `15` | Failure-counting window and lockout duration |
| `TRUST_PROXY_HOPS` | `0` | Number of reverse proxies whose `X-Forwarded-*` headers are trusted |
| `RECOVER_INTERRUPTED_SCANS` | `true` | At startup, mark scans left running by a previous process as interrupted |
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

A typical first session: log in, (admin) save your SSH credentials as credential sets, create a command template, run a scan, look at the results, then schedule it.

### 1. Log In and Manage Users

- Log in with your username and password. New users must change their password at first login.
- **Change Password** is in the user menu (top right).
- **User Management** (admin only, in the user menu): create users, optionally with admin rights; reset a user's password (they must change it at next login, and their open sessions are signed out); delete users (not yourself, and not the last admin).

See [Authentication and Roles](#authentication-and-roles) for what admins and other users can do.

### 2. SSH Authentication Options

Every combination of login method and sudo is supported:

| SSH login | Sudo on the target | What to enter |
|---|---|---|
| Password | needs a password | username, SSH password, **sudo password** |
| Password | no password (`NOPASSWD`) | username, SSH password (leave sudo password empty) |
| Private key | needs a password | username, private key, **sudo password** |
| Private key | no password (`NOPASSWD`) | username, private key |
| Private key with a passphrase | either | as above, plus the **key passphrase** |
| any | no sudo rights | works; `sudo` commands fail and root-only details are skipped |

- **Private keys**: Ed25519, RSA, ECDSA and DSA, in OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`) or PEM format. Paste the whole private key, including the BEGIN/END lines. If the key has a passphrase, enter it in **Key Passphrase**; if you forget, the scan fails with "Private key is passphrase-protected; enter the key passphrase".
- **Sudo password**: used only when sudo actually asks for one. With `NOPASSWD` sudo it is never sent.
- **Port**: the SSH port (default 22).
- The SSH, sudo and key passphrases are never shown in results, exports or logs.

### 3. Save Credential Sets (admin)

On **Credentials**, click **Add New Credential Set** and enter: username; authentication type (password or SSH key); the password, or the private key and its optional passphrase; an optional sudo password; a priority (higher is tried first); a description; and optionally **Allowed Subnets**.

> **Credential exposure.** With password authentication the SSH server receives the password itself, so every host a credential is tried against can capture it, including an unknown or compromised host in the scanned range. Trying all credential sets against a range sends *every* stored password to *every* host, and can lock accounts out. Set **Allowed Subnets** on each set (CIDRs or addresses, separated by commas or new lines) so it is only ever sent to the hosts it belongs to; hosts outside them are skipped with "credential is not allowed for this host". Prefer SSH keys, which never leave the scanner, and use `SSH_HOST_KEY_POLICY=reject` in production.

- Secrets are encrypted in the database (see [Where Credentials Are Stored](#where-credentials-are-stored)). They are never shown again: when you edit a set, leave the secret fields blank to keep the stored values. If you paste a new key, also enter its passphrase (blank means the new key has none). Tick **Remove the stored sudo password** to delete a sudo password.
- A scan can use **one** set, or **all** sets: each host is then tried with every set in priority order until one logs in. This is useful when different servers use different accounts.
- A set that is used by a schedule can't be deleted until the schedule is changed.

### 4. Create Command Templates

**Templates** lists reusable command lists that anyone can use in a scan. Admins can create them (name, description, one command per line), edit them (pencil button, then **Update Template**) and delete them. Names must be unique. Commands from a template run first, followed by any custom commands entered on the scan form.

### 5. Run a Scan

Open **Scan**:

1. **Targets**: one per line or comma-separated. If `SCAN_ALLOWED_SUBNETS` is set, every target must be inside it (Validate Subnets reports targets outside it). Single addresses (`192.168.1.10`, `2001:db8::5`), CIDR subnets (`192.168.1.0/24`, `2001:db8::/120`) or ranges (`192.168.1.1-192.168.1.10`, the short form `192.168.1.1-10`, or `2001:db8::1-2001:db8::20`). Click **Validate Subnets** to see how many addresses will be scanned, a sample, and any invalid entries. Or use the **CSV Import** tab: upload a CSV with a column named `ip`, `ip_address`, `subnet`, `address` or `network` (otherwise the first column is used); the addresses are loaded into the form for review, and invalid rows are reported.
2. **Credentials**: enter them manually (see [SSH Authentication Options](#2-ssh-authentication-options)) or, as an admin, tick **Use Saved Credential Sets** and pick one set or all of them.
3. **Commands**: pick a template and/or type custom commands, one per line. To run a command as root, start it with `sudo`, for example `sudo cat /var/log/syslog`. The [command filter](#command-filtering) rejects dangerous commands and, by default, pipes, redirects and chaining (`|`, `>`, `;`, `&&`); rejected commands are shown as **Blocked** in the results and are not run. With `COMMAND_SANITIZATION=allowlist`, only lines that appear in a template are accepted and the scan is refused if any other command is entered.
4. **Server information**: tick **Collect Server Information** for the basic profile, and also **Collect Detailed Server Profile** for the detailed one (see below).
5. **Concurrency** (hosts scanned at the same time, 1 to `MAX_CONCURRENCY`) and **Port**, then **Start Scan**.

A progress dialog shows how many hosts are done. You can close it: the scan keeps running on the server. When it finishes, click **View Results**.

Each command runs with a time limit (`SSH_COMMAND_TIMEOUT`, default 60 seconds) and its output is capped (`SSH_MAX_OUTPUT_BYTES`, default 1 MB per stream). Commands are run in a non-interactive session, so commands that wait for input (editors, `top`, prompts) time out. A single scan can include at most `MAX_SCAN_IPS` addresses (default 65536).

### Server Information Collection

- **Basic**: hostname, OS, kernel, CPU, memory, disk usage, network interfaces, uptime.
- **Detailed**: also DNS configuration, running services, listening network connections, network cards, default gateway, virtualization, login accounts, load average, installed packages (first 100; dpkg, rpm or apk) and firewall rules.

Firewall rules (`iptables`/`nft`) and hardware details (`lshw`) need root: they are read through sudo when the account has sudo rights (with or without a sudo password); otherwise those sections stay empty. Running services need systemd (or OpenRC/`service`). Sections whose tools are missing on a host are shown as not available.

### 6. View and Export Results

Open **Results**:

- The **Recent Scans** table lists your scan sessions (admins see everyone's) with their status (running, completed, failed or interrupted) and success and failure counts. Click a session to see its hosts. A scan is **interrupted** when the application restarted while it was running.
- Filter hosts by status or sudo access, or search. Click the eye button to open a host's details:
  - **Commands**: each command with its exit code, output and errors. Blocked commands are marked **Blocked**.
  - **Server Info**: the collected profile.
  - **Errors**: connection or authentication errors.
- **Export** the session as **CSV** (one row per host), **JSON** (everything, including command output and server info) or **PDF** (summary charts and the first 20 hosts). Exports are recorded in the audit log.
- Admins can delete finished (and interrupted) scans.

Times are stored in UTC and shown in your browser's local time.

### 7. Schedule Recurring Scans (admin)

On **Schedules**, click **New Schedule** and fill in:

- **Name and targets**: same format as on the scan page.
- **Credentials**: username and password or key (with optional passphrase), **or** a saved credential set. Optionally a sudo password and the SSH port. When editing, uncheck **Keep existing sudo password** and leave the field blank to remove it.
- **Commands**: a template and/or custom commands, plus the server-information options and concurrency.
- **Frequency**: hourly, daily, weekly, monthly (same day each month) or every N minutes (custom, minimum 5).
- **Start and end dates, in UTC.** The first run happens at the start date. The end date is optional, and a schedule whose end date has passed cannot be activated.

The schedule list shows each schedule's next run. Use the buttons to view, edit, deactivate/activate (pause and play icons) or delete a schedule. Each run appears as a normal scan session on **Results**, owned by the admin who created the schedule. Targets and commands are checked against `SCAN_ALLOWED_SUBNETS` and the command policy when the schedule is saved and again at every run.

The scheduler runs in the background inside the web process and checks for due schedules every 60 seconds. It starts with the app unless `START_SCHEDULER=false`. Each run is claimed atomically in the database, so even if several processes run a scheduler, a schedule is not run twice. The default single-worker gunicorn setup is still recommended. If the app was down when runs were due, the missed runs are skipped (not replayed) and the schedule continues at its next regular time.

### 8. Settings and Audit Log (admin)

**Audit Log** lists security-relevant events, newest first: sign-ins (successful, failed and locked out), sign-outs, password changes and resets, user creation and deletion, scans started (targets count, port, number of commands, credential sets used) and refused, scan exports and deletions, and every change to credential sets, command templates and schedules, plus scheduled runs. Each entry has the time (UTC), user, client address, action, outcome and target. Secrets are never recorded. The same events go to the `audit` logger, so they can be shipped to a SIEM from the application log. Filter by an action prefix such as `auth.` or `scan.`.

**Settings** shows the configuration the running instance uses: command-filter mode, host-key policy, timeouts, limits, scheduler status, database type and where the encryption key comes from. It is read-only: settings are environment variables (see [Configuration](#configuration)), and changes need a restart. The theme (light or dark) is switched with the button in the navigation bar.

### Where Credentials Are Stored

| What | Where | How |
|---|---|---|
| App user passwords (including `admin`) | `users` table in the database | bcrypt hash only |
| First admin password (generated) | `instance/initial_admin_password`, mode 600 | plain text, deleted after the first password change |
| SSH passwords, private keys, key passphrases, sudo passwords (credential sets and schedules) | database | encrypted with Fernet |
| Encryption key for the above | `ENCRYPTION_KEY` or `instance/.encryption_key` | **back it up**, never commit it |
| Passwords typed on the scan form | memory only, for that scan | not stored |
| SSH host keys (TOFU) | `instance/known_hosts` | plain text (public keys) |

The database is `instance/subnet_whisperer.db` by default, or the PostgreSQL database in `DATABASE_URL`.

## Security

Subnet Whisperer stores SSH credentials and runs commands on remote hosts. Run it on a trusted network, behind TLS, and give admin rights only to people who should be able to use every stored credential.

### Authentication and Roles

- All pages require login (Flask-Login, bcrypt password hashes, minimum length 8).
- The first admin's password comes from `ADMIN_PASSWORD` or is generated (see [First Login](#first-login)). A password change is forced at first login.
- **Admins** can: manage users; view and manage credential sets (`/credentials` and the credential API); use saved credential sets in scans; create, edit, activate and delete schedules; create, edit and delete command templates; view and delete every scan; view the audit log and settings.
- **Non-admins** can: run scans with manually entered credentials; view and export **their own** scans only (other scans return 404); list templates and use them in scans; change their own password.
- **Login throttling**: after `LOGIN_MAX_FAILURES` (5) failed logins for one username from one address, or `LOGIN_IP_MAX_FAILURES` (20) from one address, further attempts are refused with HTTP 429 for `LOGIN_LOCKOUT_MINUTES` (15). Lockouts are per address, so an attacker cannot lock the real admin out from elsewhere. Behind a reverse proxy set `TRUST_PROXY_HOPS=1` so the real client address is used. Response times do not reveal whether a username exists. The counters are kept in memory (single process).
- CSRF protection covers all forms and AJAX requests. Tokens last as long as the session.
- Logout is a POST request with a CSRF token. Session cookies are `SameSite=Lax`, and `Secure` when `SESSION_COOKIE_SECURE=true`.
- The session is signed with `SESSION_SECRET`, or with a secret generated once and stored in `instance/.secret_key`.

### Scan Scope

Set `SCAN_ALLOWED_SUBNETS` to the networks you are authorised to assess (for example `10.0.0.0/8, 192.168.10.0/24`). Scans and schedules with any target outside it are refused (HTTP 403 for scans; schedules cannot be saved and skip the run), and the refusal is audited. When it is unset, any address may be scanned. An invalid value stops the app from starting, so a typo can never silently remove the restriction. This keeps the scanner, and any user of it, from being used to probe networks outside the agreed scope.

### HTTP Security Headers

Every response carries a Content-Security-Policy (scripts only from the app, the pinned CDNs and per-request nonces; no framing; no plugins), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and `Cache-Control: no-store` (results and credentials are not kept in shared caches). With `SESSION_COOKIE_SECURE=true`, `Strict-Transport-Security` is sent as well.

### Encryption Key

SSH passwords, private keys, key passphrases and sudo passwords are encrypted with Fernet. The key is chosen in this order:

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

`COMMAND_SANITIZATION` selects the command policy:

| Mode | What may run | Strength |
|---|---|---|
| `allowlist` | only command lines that appear, verbatim, in a command template | an enforceable control |
| `enabled` (default) | anything except the always-blocked list, shell operators and restricted programs | best-effort denylist |
| `disabled` | anything except the always-blocked list | best-effort denylist |

**A denylist cannot be made bypass-proof.** Shell commands are a programming language: `python3 -c`, `perl -e`, `awk`, `base64 -d | sh`, a script already on the host, `find -exec`, an alias, or a path written differently all reach the same result. The denylist modes catch mistakes and obvious damage; do not rely on them as a control.

**Allowlist mode** turns this around: admins decide exactly which command lines exist (command templates are admin-only), and everything else is refused, both when a scan is submitted (HTTP 403, audited) and again on the worker just before a command is sent. Templates may use pipes and redirects, because an admin approved the exact line. The always-blocked checks below still apply. The scan page tells users when the allowlist is on.

**Enforce on the targets too.** The application only decides what it *sends*. What a command can *do* is decided on the target, and that is where the real boundary belongs:

- Scan with a dedicated, unprivileged account (no shell login for people, no membership in `wheel`/`sudo`/`docker`).
- If root-level data is needed, grant only specific commands in sudoers instead of `ALL`, for example:
  ```
  # /etc/sudoers.d/subnet-whisperer
  scanner ALL=(root) NOPASSWD: /usr/sbin/iptables -L -n -v, /usr/sbin/nft list ruleset, /usr/bin/lshw -class network -short
  ```
- To make the account unable to run anything else at all, pin it to a wrapper in `sshd_config` (`Match User scanner` / `ForceCommand /usr/local/bin/scanner-wrapper`) that only executes approved commands from `$SSH_ORIGINAL_COMMAND`, or restrict its key in `authorized_keys` with `command="...",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`.
- Log the account's sessions on the target (auditd / `pam_tty_audit`) so activity is attributable there as well.

Commands are tokenized like a shell (shlex) and checked before they are sent. A rejected command is simply not run; the result shows it as blocked. There is no approval workflow.

**Always blocked** (in every mode):

- `rm` recursive deletes of `/`, `/*` or `~`, in any flag order (`-rf`, `-fr`, `-r -f`, `--recursive --force`, `--no-preserve-root`), including path variants such as `/.`, `//` or `/usr/..`
- `find / ... -delete`
- `mkfs` and its variants (`mkfs.ext4`, ...)
- `dd`, `shred` or `wipefs` writing to block devices (`/dev/sd*`, `/dev/hd*`, `/dev/nvme*`, `/dev/vd*`, `/dev/xvd*`, `/dev/mmcblk*`)
- fork bombs
- `curl` or `wget` piped into `sh` or `bash`
- `shutdown`, `reboot`, `halt`, `poweroff`, `kexec`, `init 0`/`init 6`, `telinit 0`/`telinit 6` when used as commands (a word such as `halting-problem` is fine), and `systemctl`/`loginctl` power and rescue verbs (`reboot`, `poweroff`, `halt`, `suspend`, `rescue`, `emergency`, `isolate`, ...)
- `sudo -i`, `sudo -s`, `sudo su`, and starting a shell through `sudo`, `doas` or `pkexec` (`sudo bash`)
- access to `/etc/shadow`, `/etc/gshadow` and their backups, also via path variants such as `/etc/../etc/shadow` (`cat /etc/passwd` is allowed)

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

To run pipelines while keeping the filter enabled, put them in a script on the target and run the script as a single command, put the exact pipeline in a template and use `COMMAND_SANITIZATION=allowlist`, or set `COMMAND_SANITIZATION=disabled`.

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
- **Scan ownership.** Scans now belong to the user who started them, and non-admins only see their own. Scans created before this change have no owner, so only admins see them. New columns and the `audit_log` table are added automatically at startup.
- **Settings is admin-only** now, next to the new **Audit Log** page.
- **Test SSH key.** The Docker integration tests used to ship a committed private key (`tests/docker/keys/id_ed25519_valid`). It is now generated at test time and git-ignored. The old key is still in git history; it was only ever trusted by the throwaway test container, so no action is needed unless you reused it elsewhere.

## Testing

See [TESTING.md](TESTING.md) and [tests/README.md](tests/README.md). Tests set `START_SCHEDULER=false`.

## Troubleshooting

- **"Address already in use" / port 5000 busy**: on macOS the AirPlay Receiver uses port 5000. Use `PORT=5050 python main.py`, or set `HOST_PORT=5050` in `.env` for Docker (or turn off AirPlay Receiver in System Settings).
- **`setup.sh`: "Python 3.11 or higher is required"**: install a newer Python (`brew install python@3.12`, or your distribution's package) and run `PYTHON=python3.12 ./setup.sh`.
- **Where is the admin password?** `cat instance/initial_admin_password` (first start only, until it is changed), or the `ADMIN_PASSWORD` you set. See [First Login](#first-login).
- **"Host key verification FAILED"**: the host's key changed since it was first recorded (TOFU). Verify the change, then remove the host's line from `instance/known_hosts`.
- **"Private key is passphrase-protected; enter the key passphrase"**: fill in **Key Passphrase**. "wrong passphrase, or unsupported or malformed key": check the passphrase and that you pasted the complete key.
- **`sudo` commands fail**: enter the sudo password (unless the account has `NOPASSWD` sudo) and check that the account is allowed to use sudo on the target (`sudo -l`).
- **Firewall rules or network cards are empty**: they need root; give the account sudo rights and the sudo password.
- **Command shows "Blocked"**: the command filter rejected it; see [Command Filtering](#command-filtering).
- **"not in an approved command template"**: `COMMAND_SANITIZATION=allowlist` is on. Ask an admin to add the exact command line to a template.
- **"outside the authorised scan scope (SCAN_ALLOWED_SUBNETS)"**: a target is outside the configured scope. Remove it, or have the scope changed if the assessment is authorised.
- **"Skipped ... credential is not allowed for <ip>"**: the credential set's **Allowed Subnets** does not include that host, so it was not sent there.
- **"Too many failed login attempts"** (HTTP 429): wait for `LOGIN_LOCKOUT_MINUTES` (15) or try from the user's usual address; restarting the app also clears the counters. Behind a reverse proxy, set `TRUST_PROXY_HOPS` or every user shares the proxy's address.
- **Scan shows "Interrupted"**: the application restarted while the scan was running. Run it again; admins can delete the interrupted session.
- **A scan returns "not found" for a user**: non-admins only see scans they started; scans from before ownership was added are visible to admins only.
- **Command "timed out"**: it ran longer than `SSH_COMMAND_TIMEOUT` or waited for input; raise the timeout or make the command non-interactive.
- **App won't start, "Invalid encryption key from ENCRYPTION_KEY"**: the value isn't a Fernet key. Generate one as shown in [Encryption Key](#encryption-key), or unset it to use `instance/.encryption_key`.
- **"could not be decrypted (encryption key changed?)"**: restore the old key, or re-enter the credentials.
- **Permission denied on `instance/` in Docker (Linux)**: see [Persistent Storage](#persistent-storage).
- **"Too many IP addresses"**: split the scan, or raise `MAX_SCAN_IPS`.
- **Slow scans**: unreachable addresses wait for `SSH_CONNECT_TIMEOUT` (10 s); raise the concurrency or scan smaller ranges.

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
