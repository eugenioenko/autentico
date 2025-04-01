# Variables
APP_NAME=autentico

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

# Run a linter (requires `golangci-lint`)
.PHONY: lint
lint:
	golangci-lint run ./...


# Run the Go application with live reload (requires `air` installed)
.PHONY: watch
watch:
	air

# Generate swagger docs
.PHONY: docs
docs:
	swag init
	go run swagger/swagger.go
