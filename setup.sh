#!/bin/bash

# Subnet Whisperer Setup Script
# This script installs dependencies and sets up the Subnet Whisperer application

echo "=== Subnet Whisperer Setup ==="
echo "This script will install the required dependencies and set up the application."

# Check Python version
python_version=$(python3 --version 2>&1 | grep -Po '(?<=Python )\d+\.\d+')
major=$(echo $python_version | cut -d. -f1)
minor=$(echo $python_version | cut -d. -f2)

if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 7 ]); then
    echo "Error: Python 3.7 or higher is required. Found Python $python_version"
    exit 1
fi
echo "Python $python_version detected."

# Install dependencies
echo "Installing dependencies..."
# Note: In Replit, dependencies are managed through the packager tool
# This is for when setting up outside of Replit
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "Installing required packages..."
    pip install flask flask-login flask-sqlalchemy flask-wtf gunicorn matplotlib pandas paramiko psycopg2-binary sqlalchemy wtforms email-validator
fi

# Check if database exists, if not initialize it
if [ ! -d "instance" ] || [ ! -f "instance/subnet_whisperer.db" ]; then
    echo "Initializing database..."
    python migration.py
    # Run the application to create tables
    echo "Creating database tables..."
    python -c "from app import app, db; app.app_context().push(); db.create_all()"
else
    echo "Running database migrations..."
    python migration.py
fi

# Create logs directory if it doesn't exist
if [ ! -d "logs" ]; then
    echo "Creating logs directory..."
    mkdir -p logs
fi

# Set environment variables for session secret
if [ -z "$SESSION_SECRET" ]; then
    echo "Generating session secret..."
    export SESSION_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
    echo "# Add this to your .env file for persistent configuration" > .env
    echo "SESSION_SECRET=$SESSION_SECRET" >> .env
fi

echo "=== Setup Complete ==="
echo "To start the application:"
echo "1. Activate the virtual environment (if not already activated):"
echo "   source venv/bin/activate"
echo "2. Run the application:"
echo "   python main.py"
echo ""
echo "The application will be available at http://localhost:5000"
echo ""
echo "To run with gunicorn (recommended for production):"
echo "gunicorn --bind 0.0.0.0:5000 main:app"