# Variables
APP_NAME=auth-service
DB_FILE=auth.db

# Default target
.PHONY: all
all: build

# Build the Go binary
.PHONY: build
build:
	go build -o $(APP_NAME) main.go

# Run the application
.PHONY: run
run:
	go run main.go

# Format code using gofmt
.PHONY: fmt
fmt:
	gofmt -w .

# Run tests
.PHONY: test
test:
	go test ./...

# Clean up build artifacts and database file
.PHONY: clean
clean:
	rm -f $(APP_NAME) $(DB_FILE)

# Reset the database by removing it and restarting the app
.PHONY: reset-db
reset-db:
	rm -f $(DB_FILE)
	go run main.go

# Run a linter (requires `golangci-lint`)
.PHONY: lint
lint:
	golangci-lint run ./...

# Generate a new SQLite migration (example)
.PHONY: migrate
migrate:
	go run migrations/migrate.go

# Run the Go application with live reload (requires `air` installed)
.PHONY: watch
watch:
	air
