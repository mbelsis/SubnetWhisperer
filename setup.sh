#!/usr/bin/env bash
# Subnet Whisperer setup script
# Installs dependencies, initialises the database and prepares a local .env file.
# Safe to re-run: an existing .env is never overwritten, only missing keys are appended.

set -euo pipefail
cd "$(dirname "$0")"

echo "=== Subnet Whisperer Setup ==="

# ---------------------------------------------------------------------------
# Python version check (3.11+), portable across Linux and macOS
# ---------------------------------------------------------------------------
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Error: $PYTHON not found. Install Python 3.11 or newer." >&2
    exit 1
fi

if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "Error: Python 3.11 or higher is required. Found: $("$PYTHON" --version 2>&1)" >&2
    exit 1
fi
echo "$("$PYTHON" --version 2>&1) detected."

# ---------------------------------------------------------------------------
# Virtual environment: use the active one, otherwise create/reuse ./.venv
# (system and Homebrew Pythons refuse global pip installs)
# ---------------------------------------------------------------------------
if [ -n "${VIRTUAL_ENV:-}" ]; then
    echo "Using the active virtual environment: $VIRTUAL_ENV"
    PYTHON="$VIRTUAL_ENV/bin/python"
else
    if [ ! -x .venv/bin/python ]; then
        echo "Creating virtual environment in .venv ..."
        "$PYTHON" -m venv .venv
    fi
    PYTHON="$(pwd)/.venv/bin/python"
    echo "Using virtual environment: .venv"
fi
"$PYTHON" -m pip install --quiet --upgrade pip

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
echo "Installing dependencies..."
if command -v uv >/dev/null 2>&1; then
    # Install the exact versions pinned in uv.lock into the active environment
    uv export --frozen --no-dev --no-emit-project --no-hashes -o "${TMPDIR:-/tmp}/subnet-whisperer-requirements.txt"
    "$PYTHON" -m pip install --quiet -r "${TMPDIR:-/tmp}/subnet-whisperer-requirements.txt"
else
    # Fall back to the version ranges declared in pyproject.toml
    deps=$("$PYTHON" - <<'PY'
import tomllib
with open("pyproject.toml", "rb") as f:
    print("\n".join(tomllib.load(f)["project"]["dependencies"]))
PY
)
    # shellcheck disable=SC2086
    "$PYTHON" -m pip install --quiet $deps
fi

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
mkdir -p instance logs

# ---------------------------------------------------------------------------
# .env: create from .env.example if missing, then append any missing keys.
# Existing values are never changed.
# ---------------------------------------------------------------------------
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Created .env from .env.example."
    else
        touch .env
    fi
    chmod 600 .env
fi

env_has_key() {
    grep -Eq "^[[:space:]]*$1=" .env
}

append_env() {
    local key="$1" value="$2"
    if ! env_has_key "$key"; then
        echo "${key}=${value}" >> .env
        echo "Added ${key} to .env"
    fi
}

if [ -z "${SESSION_SECRET:-}" ] && ! env_has_key SESSION_SECRET; then
    append_env SESSION_SECRET "$("$PYTHON" -c 'import secrets; print(secrets.token_hex(32))')"
fi
# ENCRYPTION_KEY is deliberately not generated here: if it is unset, the app
# creates instance/.encryption_key on first start and keeps using it.

# Export the .env values so the migration step below uses the same settings as the app
set -a
# shellcheck disable=SC1091
. ./.env
set +a

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
echo "Creating / updating the database schema..."
if ! "$PYTHON" run_migrations.py; then
    echo "Error: database migrations failed. See the output above." >&2
    exit 1
fi


echo ""
echo "=== Setup Complete ==="
echo ""
echo "Admin account:"
echo "  Username: admin"
echo "  Password: the value of ADMIN_PASSWORD if it was set when the database was"
echo "            first created; otherwise a random password that was logged (see the"
echo "            output above) and written to instance/initial_admin_password."
echo "            You must change it at first login."
echo ""
echo "Start the app:"
echo "  source .venv/bin/activate        # skip if you used your own virtualenv"
echo "  set -a; . ./.env; set +a         # the app does not read .env by itself"
echo "  python main.py                   # http://127.0.0.1:5000 (set PORT=5050 if 5000 is busy, e.g. macOS AirPlay)"
echo ""
echo "Production (gunicorn):"
echo "  gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 main:app"
echo ""
echo "Keep and back up instance/.encryption_key (or ENCRYPTION_KEY): without it,"
echo "stored credentials cannot be decrypted."
