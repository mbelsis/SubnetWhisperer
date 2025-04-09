.PHONY: build run run-postgres stop clean

build:
	docker-compose build

run:
	export DATABASE_URL="sqlite:///instance/subnet_whisperer.db" && docker-compose up web

run-postgres:
	export DATABASE_URL="postgresql://postgres:postgres@db/subnet_whisperer" && docker-compose up

stop:
	docker-compose down

clean: stop
	docker-compose down -v
	docker system prune -f

help:
	@echo "Available commands:"
	@echo "  make build        - Build the Docker image"
	@echo "  make run          - Run the application with SQLite"
	@echo "  make run-postgres - Run the application with PostgreSQL"
	@echo "  make stop         - Stop all running containers"
	@echo "  make clean        - Stop containers and clean up volumes"