# Variables
APP_NAME=autentico
SWAG=$(shell go env GOPATH)/bin/swag

# Default target
all: build

# Build Go binary
build-go: 
	go build -o $(APP_NAME) main.go

# Build admin UI + Go binary
build: admin-ui-build
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(APP_NAME) main.go

# Run the application
run:
	go run main.go start

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
	$(SWAG) init
	npx @redocly/cli build-docs ./docs/swagger.yaml --output=./docs/index.html

# Build admin UI and copy to pkg/admin/dist
admin-ui-build: generate-docs
	cd admin-ui && pnpm install && pnpm run build
	rm -rf pkg/admin/dist
	cp -r admin-ui/dist pkg/admin/dist
	cp docs/index.html pkg/admin/dist/docs.html


docker-build:
	docker build -t autentico:tag .

docker-compose:
	docker compose up -d

# Fresh start: wipe local DB, rebuild, init, and launch
fresh: build
	rm -f ./db/autentico.db .env
	./$(APP_NAME) init
	./$(APP_NAME) start
