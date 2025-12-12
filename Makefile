.PHONY: build run dev test clean docker-up docker-down migrate help

# Default target
help:
	@echo "Available commands:"
	@echo "  make build       - Build the project in release mode"
	@echo "  make run         - Run the project in release mode"
	@echo "  make dev         - Run the project in development mode with hot reload"
	@echo "  make test        - Run all tests"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make docker-up   - Start Docker containers (postgres, redis)"
	@echo "  make docker-down - Stop Docker containers"
	@echo "  make migrate     - Run database migrations"
	@echo "  make fmt         - Format code"
	@echo "  make lint        - Run clippy linter"

# Build commands
build:
	cargo build --release

run:
	cargo run --release

dev:
	cargo watch -x run

# Test commands
test:
	cargo test

test-verbose:
	cargo test -- --nocapture

# Code quality
fmt:
	cargo fmt

lint:
	cargo clippy -- -D warnings

check:
	cargo check

# Clean
clean:
	cargo clean

# Docker commands
docker-up:
	docker-compose up -d postgres redis

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Database commands
migrate:
	sqlx migrate run

migrate-create:
	@read -p "Migration name: " name; \
	sqlx migrate add $$name

# Full setup
setup: docker-up
	@echo "Waiting for database to be ready..."
	@sleep 3
	$(MAKE) migrate
	@echo "Setup complete!"

# Development workflow
dev-setup:
	cargo install cargo-watch
	cargo install sqlx-cli
	cp .env.example .env
	@echo "Development setup complete! Edit .env file with your configuration."
