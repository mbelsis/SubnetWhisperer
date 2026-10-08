# Uses the Compose v2 plugin by default. Override with: make COMPOSE=docker-compose <target>
COMPOSE ?= docker compose

.DEFAULT_GOAL := help
.PHONY: help build run run-postgres stop clean prune

help:
	@echo "Available commands:"
	@echo "  make build        - Build the Docker image"
	@echo "  make run          - Run the application with SQLite"
	@echo "  make run-postgres - Run the application with PostgreSQL (needs POSTGRES_PASSWORD)"
	@echo "  make stop         - Stop all running containers"
	@echo "  make clean        - Stop containers and remove this project's containers, networks and volumes"
	@echo "  make prune        - Host-wide 'docker system prune' (asks for confirmation)"

build:
	$(COMPOSE) build

run:
	mkdir -p instance logs
	$(COMPOSE) up web

run-postgres:
	./docker-start.sh postgres

stop:
	$(COMPOSE) --profile postgres down

# Removes only this project's containers, networks and named volumes
# (including the PostgreSQL data volume). ./instance and ./logs are kept.
clean:
	$(COMPOSE) --profile postgres down -v --remove-orphans

# Affects ALL Docker resources on this host, not just this project.
prune:
	@printf "This runs 'docker system prune' for the WHOLE host. Continue? [y/N] "; \
	read ans; \
	if [ "$$ans" = "y" ] || [ "$$ans" = "Y" ]; then docker system prune; else echo "Aborted."; fi
