#!/bin/bash

# Create necessary directories
mkdir -p instance logs

# Check if the user wants to use PostgreSQL
if [ "$1" == "postgres" ]; then
    echo "Starting Subnet-Whisperer with PostgreSQL database..."
    docker-compose --profile postgres up web-postgres db
else
    echo "Starting Subnet-Whisperer with SQLite database..."
    docker-compose up web
fi
