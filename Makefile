.PHONY: run build test clean migrate migrate-down

# Default binary name
BINARY_NAME=zx-auth-service

# Build the application
build:
	go build -o bin/$(BINARY_NAME) ./cmd/server

# Run the application
run:
	go run ./cmd/server

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Install dependencies
deps:
	go mod download
	go mod tidy

# Database commands
db-create:
	@echo "Creating database..."
	@PGPASSWORD=$(DB_PASSWORD) createdb -h $(DB_HOST) -p $(DB_PORT) -U $(DB_USER) $(DB_NAME) || echo "Database already exists"

db-drop:
	@echo "Dropping database..."
	@PGPASSWORD=$(DB_PASSWORD) dropdb -h $(DB_HOST) -p $(DB_PORT) -U $(DB_USER) $(DB_NAME) || echo "Database does not exist"

db-reset: db-drop db-create migrate

# Run database migrations
migrate:
	@echo "Running database migrations..."
	go run ./cmd/server -migrate

# Roll back database migrations
migrate-down:
	@echo "Rolling back database migrations..."
	go run ./cmd/server -migrate-down

# Generate API documentation (placeholder)
docs:
	@echo "Generating API documentation..."
	# Add your documentation generation command here

# Development mode with hot reload (requires air: go install github.com/cosmtrek/air@latest)
dev:
	air

# Security check
security:
	go vet ./...
	gosec ./... 