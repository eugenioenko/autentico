# Variables
APP_NAME=autentico
SWAG=$(shell go env GOPATH)/bin/swag

# Default target
all: build

# Build Go binary
build-go:
	go build -o $(APP_NAME) main.go

# Build admin UI + account UI + Go binary
build: admin-ui-build account-ui-build
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(APP_NAME) main.go
	@echo ""
	@echo "Build complete. Binary: ./$(APP_NAME)"
	@echo ""
	@echo "Next steps:"
	@echo "  ./$(APP_NAME) init     # generate .env with keys and secrets"
	@echo "  ./$(APP_NAME) start    # start the server"
	@echo ""
	@echo "Using Autentico? We'd love to hear from you."
	@echo "Share your use case: https://github.com/eugenioenko/autentico/discussions/113"
	@echo ""

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

# Run functional black-box tests (builds binary if needed, starts real server)
.PHONY: test-functional
test-functional: build-go
	cd tests/functional && pnpm install && pnpm test

# Run e2e Go tests
.PHONY: test-e2e
test-e2e:
	go test -p 1 -v ./tests/e2e/...

# Run a linter (requires `golangci-lint`)
lint:
	golangci-lint run ./...


# Install required tools if missing
tool-check:
	@which go > /dev/null 2>&1 || (echo "Error: Go is not installed. Install it from https://go.dev/dl/" && exit 1)
	@which $(SWAG) > /dev/null 2>&1 || (echo "Installing swag..." && go install github.com/swaggo/swag/cmd/swag@latest)

# Generate swagger docs
generate-docs: tool-check
	$(SWAG) init

# Build admin UI and copy to pkg/admin/dist
admin-ui-build: generate-docs
	cd admin-ui && pnpm install && pnpm run build
	rm -rf pkg/admin/dist
	cp -r admin-ui/dist pkg/admin/dist

# Build account UI and copy to pkg/account/dist
account-ui-build:
	cd account-ui && pnpm install && pnpm run build
	rm -rf pkg/account/dist
	cp -r account-ui/dist pkg/account/dist

# Fast build: skip tsc type-checking in UI builds
fast: admin-ui-build-fast account-ui-build-fast
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(APP_NAME) main.go
	@echo ""
	@echo "Fast build complete. Binary: ./$(APP_NAME)"
	@echo ""

# Build admin UI (fast, no tsc) and copy to pkg/admin/dist
admin-ui-build-fast:
	cd admin-ui && pnpm install && pnpm run build:fast
	rm -rf pkg/admin/dist
	cp -r admin-ui/dist pkg/admin/dist

# Build account UI (fast, no tsc) and copy to pkg/account/dist
account-ui-build-fast:
	cd account-ui && pnpm install && pnpm run build:fast
	rm -rf pkg/account/dist
	cp -r account-ui/dist pkg/account/dist

docker-build:
	docker build -t autentico:tag .

docker-compose:
	docker compose up -d

# Fresh start: wipe local DB, rebuild, init, and launch
fresh: build
	rm -f ./autentico.db .env
	./$(APP_NAME) init
	./$(APP_NAME) start

# Stress tests — run via Docker (no k6 install required)
# Uses --network=host so k6 can reach a locally running server.
BASE_URL    ?= http://localhost:9999
USERNAME    ?= admin
PASSWORD    ?= password
CLIENT_ID   ?= stress-test
REDIRECT_URI?= http://localhost:8080/stress/callback

K6=docker run --rm -i --network=host \
	-e BASE_URL=$(BASE_URL) \
	-e USERNAME=$(USERNAME) \
	-e PASSWORD=$(PASSWORD) \
	-e CLIENT_ID=$(CLIENT_ID) \
	-e REDIRECT_URI=$(REDIRECT_URI) \
	-v $(PWD)/stress:/scripts grafana/k6

stress-smoke:
	$(K6) run /scripts/smoke.js

stress-load:
	$(K6) run /scripts/load.js

stress-spike:
	$(K6) run /scripts/spike.js

stress-ratelimit:
	$(K6) run /scripts/rate_limit.js

stress-debug:
	$(K6) run /scripts/debug.js

stress-ceiling:
	$(K6) run /scripts/ceiling.js

# Start server with rate limiting disabled (for stress testing only — not for production)
stress-server:
	AUTENTICO_RATE_LIMIT_RPS=0 AUTENTICO_RATE_LIMIT_RPM=0 ./$(APP_NAME) start

# ── OIDC Conformance ─────────────────────────────────────────────────────────
# Runs the OpenID Foundation conformance suite locally via Docker.
# conformance-server: start Autentico with settings suitable for conformance testing
# conformance-suite:  pull and start the conformance suite at https://localhost:8443
# conformance-stop:   stop and remove the conformance suite container

CONFORMANCE_PORT ?= 8443

conformance-server:
	AUTENTICO_RATE_LIMIT_RPS=0 AUTENTICO_RATE_LIMIT_RPM=0 \
	AUTENTICO_CSRF_SECURE_COOKIE=false \
	AUTENTICO_IDP_SESSION_SECURE=false \
	AUTENTICO_APP_URL=http://172.17.0.1:9999 \
	./$(APP_NAME) start

conformance-suite:
	docker run -d --name oidc-conformance --network=host \
		-p $(CONFORMANCE_PORT):$(CONFORMANCE_PORT) \
		openidcertification/conformance-suite
	@echo "Conformance suite running at https://localhost:$(CONFORMANCE_PORT)"

conformance-stop:
	docker stop oidc-conformance && docker rm oidc-conformance
