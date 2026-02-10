# Variables
APP_NAME=autentico

# Default target
all: build

# Build admin UI + Go binary
build: admin-ui-build
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
	npx @redocly/cli build-docs ./docs/swagger.yaml --output=./docs/index.html

# Run swagger
.PHONY: docs
docs:
	go run cmd/swagger.go

# Build admin UI and copy to pkg/admin/dist
admin-ui-build:
	cd admin-ui && pnpm install && pnpm run build
	rm -rf pkg/admin/dist
	cp -r admin-ui/dist pkg/admin/dist


docker-build:
	docker build -t autentico:tag .

docker-compose:
	docker compose up -d

generate-key:
	openssl genpkey -algorithm RSA -out ./db/private_key.pem -pkeyopt rsa_keygen_bits:2048
