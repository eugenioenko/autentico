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
	npx --yes @redocly/cli build-docs ./docs/swagger.yaml --output=./docs/index.html

# Build admin UI and copy to pkg/admin/dist
admin-ui-build: generate-docs
	pnpm install
	cd admin-ui && pnpm run build
	rm -rf pkg/admin/dist
	cp -r admin-ui/dist pkg/admin/dist
	cp docs/index.html pkg/admin/dist/docs.html

# Build account UI and copy to pkg/account/dist
account-ui-build:
	pnpm install
	cd account-ui && pnpm run build
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
