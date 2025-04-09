#!/bin/bash

# Create necessary directories
mkdir -p instance logs

# Check if the user wants to use PostgreSQL
if [ "$1" == "postgres" ]; then
    echo "Starting Subnet-Whisperer with PostgreSQL database..."
    export DATABASE_URL="postgresql://postgres:postgres@db/subnet_whisperer"
    docker-compose up
else
    echo "Starting Subnet-Whisperer with SQLite database..."
    export DATABASE_URL="sqlite:///instance/subnet_whisperer.db"
    # Start only the web service if using SQLite
    docker-compose up web
fi