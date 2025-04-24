# Variables
APP_NAME=autentico

# Default target
all: build

# Build the Go binary
build:
	go build -o $(APP_NAME) main.go

# Run the application
run:
	go run main.go

# Format code using gofmt
fmt:
	gofmt -w .

# Run tests
.PHONY: test
test:
	go test ./...

# Run a linter (requires `golangci-lint`)
lint:
	golangci-lint run ./...


generate-docs:
	swag init
# Generate swagger docs
.PHONY: docs
docs:
	go run cmd/swagger.go
