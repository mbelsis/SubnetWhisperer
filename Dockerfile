# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage: resolve the pinned dependencies from uv.lock and install them
# into a virtual environment. Compilers and -dev headers live only here.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Pinned uv binary, used only to export the lock file
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

WORKDIR /build
COPY pyproject.toml uv.lock ./

# Export exactly the versions pinned in uv.lock (no dev deps, not the project itself)
RUN uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt \
    && python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Runtime stage: slim image with the prebuilt virtualenv and the app code only
# ---------------------------------------------------------------------------
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=main.py

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Non-root user (uid 1000). Bind-mounted ./instance and ./logs must be
# writable by this uid on Linux hosts.
RUN adduser --disabled-password --gecos '' --uid 1000 appuser

# Application code (tests/, instance/, .env etc. are excluded by .dockerignore)
COPY --chown=appuser:appuser . .

RUN mkdir -p instance logs && chown -R appuser:appuser instance logs

USER appuser

EXPOSE 5000

# One worker process so only one scheduler runs per container (scheduled runs
# are also claimed atomically in the database). Threads handle concurrency.
# No --reload: this is the production entrypoint.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "main:app"]
