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
	go test -p 1 -v ./...

# Run a linter (requires `golangci-lint`)
lint:
	golangci-lint run ./...


# Generate swagger docs
generate-docs:
	swag init
	npx @redocly/cli build-docs ./docs/swagger.yaml --output=./docs/autentico-api.html

# Run swagger
.PHONY: docs
docs:
	go run cmd/swagger.go

docker-build:
	docker build -t autentico:tag .

docker-compose:
	docker compose up -d

generate-key:
	openssl genpkey -algorithm RSA -out ./db/private_key.pem -pkeyopt rsa_keygen_bits:2048
