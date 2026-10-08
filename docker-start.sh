#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Prefer the Compose v2 plugin, fall back to the legacy docker-compose binary
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "Error: Docker Compose is not installed." >&2
    exit 1
fi

# Bind-mounted folders (the container runs as uid 1000 and must be able to write here)
mkdir -p instance logs

# Load POSTGRES_PASSWORD etc. from .env for the check below (compose reads .env itself)
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

if [ "${1:-}" == "postgres" ]; then
    if [ -z "${POSTGRES_PASSWORD:-}" ]; then
        echo "Error: POSTGRES_PASSWORD is not set. Set it in your shell or in .env (see .env.example)." >&2
        exit 1
    fi
    echo "Starting Subnet Whisperer with PostgreSQL database..."
    "${COMPOSE[@]}" --profile postgres up web-postgres db
else
    echo "Starting Subnet Whisperer with SQLite database..."
    "${COMPOSE[@]}" up web
fi
