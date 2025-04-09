FROM python:3.11-slim

WORKDIR /app

# Install dependencies for SSH & database connectivity
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libffi-dev \
    openssh-client \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first to leverage Docker cache
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir flask flask-login flask-sqlalchemy flask-wtf gunicorn matplotlib pandas paramiko psycopg2-binary sqlalchemy wtforms email-validator cryptography bcrypt

# Copy application code
COPY . .

# Create necessary directories if they don't exist
RUN mkdir -p instance logs

# Create a non-root user to run the application
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=main.py

# Command to run the application with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--reuse-port", "--reload", "main:app"]