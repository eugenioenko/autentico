# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Autentico is an OpenID Connect (OIDC) authentication server built with Go, using SQLite for persistence. It implements OAuth 2.0 flows including Authorization Code, Password Credentials, and Refresh Token grants.

## Common Commands

```bash
# Build
make build                    # or: go build -o autentico main.go

# Run
make run                      # or: go run main.go

# Test
make test                     # or: go test -p 1 -v ./...
go test ./pkg/token/...       # Run tests for a specific package
go test -run TestCreateUser ./pkg/user/...  # Run a single test

# Lint and format
make lint                     # Requires golangci-lint
make fmt                      # Format code with gofmt
go vet ./...                  # Static analysis

# Generate RSA key for token signing (required before first run)
make generate-key

# Swagger documentation
make docs                     # Serves Swagger UI at localhost:8888
make generate-docs            # Regenerate swagger files
```

## Architecture

### Package Structure

Each feature package in `pkg/` follows a consistent pattern:
- `model.go` - Data structs, request/response types, validation using `ozzo-validation`
- `handler.go` - HTTP handlers with Swagger annotations
- `create.go`, `read.go`, `update.go`, `delete.go` - Database CRUD operations
- `service.go` - Business logic helpers

### Key Packages

| Package | Purpose |
|---------|---------|
| `pkg/authorize` | `/oauth2/authorize` - Initiates auth flow, renders login page |
| `pkg/login` | `/oauth2/login` - Handles login form submission, creates auth codes |
| `pkg/token` | `/oauth2/token` - Token exchange, refresh, revocation |
| `pkg/client` | `/oauth2/register` - OAuth2 client registration (admin only) |
| `pkg/user` | User CRUD operations |
| `pkg/session` | Session management and logout |
| `pkg/db` | SQLite database initialization and schema |
| `pkg/middleware` | HTTP middleware (CORS, CSRF, logging, auth) |
| `pkg/jwtutil` | JWT validation utilities |
| `pkg/key` | RSA key loading and JWK generation |

### OAuth2 Flow

1. Client redirects to `/oauth2/authorize` → renders login page from `view/login.html`
2. User submits credentials to `/oauth2/login` → creates auth code, redirects back
3. Client exchanges code at `/oauth2/token` → returns access/refresh tokens
4. Tokens are JWTs signed with RS256 using the private key from `db/private_key.pem`

### Configuration

Settings loaded from `autentico.json` at startup, with defaults in `pkg/config/config.go`. Access via `config.Get()`.

### Database

SQLite database initialized by `db.InitDB()`. Schema defined in `pkg/db/db.go`. Tables: `users`, `tokens`, `sessions`, `auth_codes`, `clients`.

### Testing

Tests use `db.InitTestDB("../../db/test.db")` to create isolated test databases. The `tests/utils/test_db.go` provides `WithTestDB(t)` helper. Tests run with `-p 1` flag (sequential) to avoid database conflicts.

### Response Patterns

- Success: `utils.WriteApiResponse(w, data, statusCode)` or `utils.SuccessResponse(w, data)`
- OAuth errors: `utils.WriteErrorResponse(w, statusCode, "error_type", "description")`
- Uses `model.ApiResponse[T]` for wrapped responses, `model.AuthErrorResponse` for OAuth errors
