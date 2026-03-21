.PHONY: build run run-postgres stop clean

build:
	docker-compose build

run:
	docker-compose up web

run-postgres:
	docker-compose --profile postgres up web-postgres db

stop:
	docker-compose down
	docker-compose --profile postgres down

clean: stop
	docker-compose down -v
	docker-compose --profile postgres down -v
	docker system prune -f

help:
	@echo "Available commands:"
	@echo "  make build        - Build the Docker image"
	@echo "  make run          - Run the application with SQLite"
	@echo "  make run-postgres - Run the application with PostgreSQL"
	@echo "  make stop         - Stop all running containers"
	@echo "  make clean        - Stop containers and clean up volumes"
