# Autentico - OIDC Identity Provider

[![Test Coverage](https://img.shields.io/badge/coverage-78.1%25-green.svg)](https://github.com/eugenioenko/autentico)
[![Tests](https://img.shields.io/badge/tests-336-blue.svg)](https://github.com/eugenioenko/autentico)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Auténtico is a lightweight OpenID Connect (OIDC) Identity Provider (IdP) built with Go. It provides standards-compliant authentication and identity management for your applications, issuing and managing identity tokens, access tokens, and user sessions. Auténtico uses SQLite for persistence, making it easy to deploy as a standalone IdP without external database dependencies.**

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture Overview](#architecture-overview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation & Running](#installation--running)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Endpoints](#endpoints)
- [Supported Grant Types](#supported-grant-types)
- [Client Interaction Examples](#client-interaction-examples)
  - [Register an OAuth2 Client](#register-an-oauth2-client-admin-only)
  - [Register a Public Client](#register-a-public-client-spamobile)
  - [Register a User](#register-a-user)
  - [Authorization Request](#authorization-request)
  - [Token Exchange](#token-exchange)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Features

Autentico provides a full-featured OIDC Identity Provider with the following capabilities:

- **OIDC Discovery**: Publishes `/.well-known/openid-configuration` so relying parties can auto-discover endpoints, supported scopes, and signing keys.
- **ID Token Issuance**: Issues RS256-signed ID tokens containing standard OIDC claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nonce`).
- **UserInfo Endpoint**: Serves authenticated identity claims via `/oauth2/userinfo` per the OIDC Core specification.
- **JWK Set Endpoint**: Exposes public signing keys at `/oauth2/certs` for token verification by relying parties.
- **Authorization Code Flow**: Implements the recommended secure flow for web and mobile applications.
- **Dynamic Client Registration**: Register and manage OAuth2 clients (relying parties) via REST API with support for confidential and public client types.
- **Client Authentication**: Supports `client_secret_basic` (HTTP Basic Auth) and `client_secret_post` (form parameters) authentication methods.
- **Refresh Token Support**: Allows relying parties to obtain new access tokens without re-authenticating the user.
- **Token Introspection & Revocation**: Provides endpoints for validating and invalidating tokens (RFC 7009, RFC 7662).
- **Session Management**: Manages user sessions with configurable idle timeouts and logout support.
- **Lightweight & Self-Contained**: Single binary with embedded SQLite — no external database or infrastructure required.
- **CSRF Protection**: Utilizes `gorilla/csrf` for protection against Cross-Site Request Forgery attacks on relevant endpoints.

---

## Tech Stack

- **Go (Golang)**: Single-binary deployment with strong performance and type safety.
- **SQLite**: Embedded database — no external database server required.
- **RS256 (RSA) JWT Signing**: Industry-standard asymmetric signing for ID and access tokens.
- **Gorilla Toolkit**: CSRF protection middleware.
- **Testify**: Test assertions and mocking.
- **Swagger/OpenAPI**: Interactive API documentation.

---

## Architecture Overview

Autentico is structured as a modular Go application. Each package in `pkg/` encapsulates a distinct area of IdP functionality:

| Package          | IdP Role                                                                                                   |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| `pkg/authorize`  | Handles the OIDC authorization endpoint — renders the login page and initiates the auth flow               |
| `pkg/login`      | Processes user authentication and issues authorization codes                                               |
| `pkg/token`      | Token endpoint — issues ID tokens, access tokens, and refresh tokens; handles introspection and revocation |
| `pkg/wellknown`  | Serves the OIDC discovery document (`/.well-known/openid-configuration`)                                   |
| `pkg/key`        | RSA key management and JWK Set generation for token verification                                           |
| `pkg/client`     | OAuth2 client (relying party) registration and management                                                  |
| `pkg/user`       | User identity storage and credential management                                                            |
| `pkg/session`    | User session lifecycle, idle timeouts, and logout                                                          |
| `pkg/middleware` | HTTP middleware (CORS, CSRF, logging, authentication)                                                      |
| `pkg/config`     | Application configuration                                                                                  |
| `pkg/db`         | SQLite database initialization and schema                                                                  |

The `main.go` file initializes the configuration, database, and routes, and starts the HTTP server. The login page is served from the `view/` directory.

---

## Getting Started

### Prerequisites

- Go 1.21 or later installed on your system.
- `make` (optional, for using Makefile commands).

### Installation & Running

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/eugenioenko/autentico.git
    cd autentico
    ```

2.  **Build the application:**

    ```bash
    make build
    # Or directly using Go:
    # go build autentico main.go
    ```

3.  **Generate a private key certificate (required for token signing):**

    You can use the Makefile target:

    ```bash
    make generate-key
    ```

    Or run the original command directly:

    ```bash
    openssl genpkey -algorithm RSA -out ./db/private_key.pem -pkeyopt rsa_keygen_bits:2048
    ```

4.  **Create the first admin user:**

    On a fresh install there are no users. Use the `create-admin` command to bootstrap the first admin:

    ```bash
    ./autentico create-admin --email="admin@example.com" --password="YourSecurePassword"
    ```

    This admin account can then be used to register OAuth2 clients via `/oauth2/register` and create additional users via `/user`.

5.  **Run the application:**
    ```bash
    make run
    # Or directly:
    # ./autentico
    ```
    The server will start, by default, on `http://localhost:9999`.

---

## Configuration

Application settings are loaded from `autentico.json` at startup. Create this file in the project root directory to override default values. Only the fields you want to change need to be specified; all others will use defaults.

**Example `autentico.json`:**

```json
{
  "appDomain": "myapp.example.com",
  "appPort": "8080",
  "appUrl": "https://myapp.example.com",
  "authAccessTokenSecret": "your-secure-secret-here",
  "authRefreshTokenSecret": "your-secure-refresh-secret",
  "authCSRFProtectionSecretKey": "32-byte-csrf-secret-key-here!!",
  "authRefreshTokenAsSecureCookie": true,
  "authCSRFSecureCookie": true
}
```

### Configuration Options

| **JSON Field**                    | **Description**                                                                   | **Default Value**              |
| --------------------------------- | --------------------------------------------------------------------------------- | ------------------------------ |
| `appDomain`                       | The domain name of the application.                                               | `localhost`                    |
| `appHost`                         | The host and port combination (e.g., `localhost:9999`).                           | `localhost:9999`               |
| `appPort`                         | The port on which the application runs.                                           | `9999`                         |
| `appUrl`                          | The full base URL of the application.                                             | `http://localhost:9999`        |
| `appEnableCORS`                   | If `true`, enables CORS middleware.                                               | `true`                         |
| `appOAuthPath`                    | The base path for OAuth2 endpoints (e.g., `/oauth2`).                             | `/oauth2`                      |
| `appAuthIssuer`                   | The issuer URL for tokens.                                                        | `http://localhost:9999/oauth2` |
| `dbFilePath`                      | The file path for the SQLite database.                                            | `./db/auth.db`                 |
| `authAccessTokenSecret`           | Secret key used to sign access tokens. **Change this in production!**             | `your-secret-here`             |
| `authAccessTokenExpiration`       | Duration for which access tokens are valid (e.g., `15m`, `1h`).                   | `15m`                          |
| `authRefreshTokenSecret`          | Secret key used to sign refresh tokens. **Change this in production!**            | `your-secret-here`             |
| `authRefreshTokenExpiration`      | Duration for which refresh tokens are valid (e.g., `720h` for 30 days).           | `720h`                         |
| `authRefreshTokenCookieName`      | Name of the cookie storing the refresh token.                                     | `autentico_refresh_token`      |
| `authRefreshTokenAsSecureCookie`  | If `true`, sets the Secure flag on the refresh token cookie (requires HTTPS).     | `false`                        |
| `authDefaultClientID`             | Default client ID for the application if dynamic client registration is not used. | `el_autentico_!`               |
| `authDefaultIssuer`               | Default issuer override (empty uses `appAuthIssuer`).                             | `""`                           |
| `authAuthorizationCodeExpiration` | Duration for which authorization codes are valid.                                 | `10m`                          |
| `authAllowedRedirectURIs`         | A list of allowed redirect URIs for OAuth2 client flows.                          | `[]`                           |
| `authCSRFProtectionSecretKey`     | 32-byte secret key for CSRF protection. **Generate and set this in production!**  | `your-secret-here`             |
| `authCSRFSecureCookie`            | If `true`, sets the Secure flag on the CSRF cookie (requires HTTPS).              | `false`                        |
| `authJwkCertKeyID`                | The key ID used in JWK (JSON Web Key) responses.                                  | `autentico-key-1`              |
| `authPrivateKeyFile`              | Path to the RSA private key PEM file for token signing.                           | `./db/private_key.pem`         |
| `authAccessTokenAudience`         | List of audiences to include in access tokens.                                    | `["el_autentico_!"]`           |
| `authRealmAccessRoles`            | List of realm access roles to include in tokens.                                  | `[]`                           |
| `validationMinUsernameLength`     | Minimum length for usernames.                                                     | `4`                            |
| `validationMaxUsernameLength`     | Maximum length for usernames.                                                     | `64`                           |
| `validationMinPasswordLength`     | Minimum length for passwords.                                                     | `6`                            |
| `validationMaxPasswordLength`     | Maximum length for passwords.                                                     | `64`                           |
| `validationUsernameIsEmail`       | If `true`, usernames must be valid email addresses.                               | `true`                         |
| `validationEmailRequired`         | If `true`, email is required for user registration.                               | `false`                        |
| `swaggerPort`                     | Port on which the Swagger documentation server runs.                              | `8888`                         |

---

## API Documentation

Autentico provides comprehensive API documentation:

1.  **Static HTML Documentation**:
    A pre-generated, detailed HTML API reference is available.
    - [Autentico API Documentation (GitHub Pages)](https://eugenioenko.github.io/autentico/autentico-api.html)
    - You can also find this at `/docs/autentico-api.html` in the repository.

2.  **Swagger UI / OpenAPI Specification**:
    To explore the API interactively using Swagger UI:
    ```bash
    make docs
    ```
    This command starts a local server (default: `http://localhost:8888`) serving the Swagger UI.
    - Access it at: [http://localhost:8888/swagger/index.html](http://localhost:8888/swagger/index.html)
    - The OpenAPI specification files (`swagger.json`, `swagger.yaml`) are located in the `/docs` directory.

---

## Endpoints

### OIDC Discovery & Identity

| Endpoint                            | Method | Description                                                            |
| ----------------------------------- | ------ | ---------------------------------------------------------------------- |
| `/.well-known/openid-configuration` | GET    | OIDC discovery document — relying parties use this to auto-configure   |
| `/oauth2/certs`                     | GET    | JWK Set — public keys for verifying tokens issued by this IdP          |
| `/oauth2/authorize`                 | GET    | Authorization endpoint — initiates the authentication flow             |
| `/oauth2/token`                     | POST   | Token endpoint — issues ID tokens, access tokens, and refresh tokens   |
| `/oauth2/userinfo`                  | GET    | UserInfo endpoint — returns identity claims for the authenticated user |
| `/oauth2/introspect`                | POST   | Token introspection (RFC 7662)                                         |
| `/oauth2/revoke`                    | POST   | Token revocation (RFC 7009)                                            |
| `/oauth2/logout`                    | POST   | Ends the user session                                                  |

### User Management

| Endpoint        | Method | Description                  |
| --------------- | ------ | ---------------------------- |
| `/users/create` | POST   | Register a new user identity |

### Client Registration (Admin Only)

Relying parties (OAuth2 clients) are managed via these endpoints. All require admin authentication.

| Endpoint                       | Method | Description                              |
| ------------------------------ | ------ | ---------------------------------------- |
| `/oauth2/register`             | POST   | Register a new relying party             |
| `/oauth2/register`             | GET    | List all registered relying parties      |
| `/oauth2/register/{client_id}` | GET    | Get a specific relying party             |
| `/oauth2/register/{client_id}` | PUT    | Update a relying party's configuration   |
| `/oauth2/register/{client_id}` | DELETE | Deactivate a relying party (soft delete) |

---

## Supported Grant Types

Autentico supports the following OAuth 2.0 / OIDC grant types:

- **Authorization Code** — The recommended flow for web and native applications. The IdP authenticates the user, issues an authorization code, and the relying party exchanges it for ID + access tokens.
- **Resource Owner Password Credentials** — Direct credential exchange. Provided for trusted or legacy clients; not recommended for new applications.
- **Refresh Token** — Obtain new access tokens without re-authenticating the user.

---

## Client Interaction Examples

Autentico supports dynamic client registration via the `/oauth2/register` API. Admin users can register relying parties (OAuth2 clients), which are then validated during authorization and token flows.

### Register an OAuth2 Client (Admin Only)

Register a new client application. This requires an admin user's access token:

```bash
# First, obtain an admin access token (admin user must exist)
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin@example.com&password=AdminPassword123!" \
  | jq -r '.access_token')

# Register a new confidential client
curl -X POST http://localhost:8080/oauth2/register \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["https://myapp.com/callback", "http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "client_type": "confidential",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

**Response:**

```json
{
  "client_id": "abc123xyz...",
  "client_secret": "generated_secret_shown_once",
  "client_secret_expires_at": 0,
  "client_name": "My Application",
  "client_type": "confidential",
  "redirect_uris": [
    "https://myapp.com/callback",
    "http://localhost:3000/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

> **Important**: The `client_secret` is only shown once during registration. Store it securely.

### Register a Public Client (SPA/Mobile)

For single-page applications or mobile apps that cannot securely store secrets:

```bash
curl -X POST http://localhost:8080/oauth2/register \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My SPA",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code"],
    "client_type": "public"
  }'
```

### Register a User

Create a new user via the `/users/create` endpoint:

```bash
curl -X POST http://localhost:9999/users/create \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "SecurePassword123!", "email": "user@example.com"}'
```

### Authorization Request

Redirect the user to the `/oauth2/authorize` endpoint to start the login process.

**Using JavaScript:**

```javascript
const authServerUrl = "http://localhost:9999/oauth2/authorize";
const params = new URLSearchParams({
  response_type: "code", // For Authorization Code Flow
  redirect_uri: "https://your-client-app.com/callback", // Must be in AuthAllowedRedirectURIs
  scope: "openid profile email", // Standard OIDC scopes
  state: "callback_state", // Recommended
});

window.location.href = `${authServerUrl}?${params.toString()}`;
```

**Using `curl` to construct the URL for manual testing:**

```bash
# Note: This curl command just constructs the URL. You'd then open this URL in a browser.
# Replace placeholders accordingly.
# Ensure the redirect_uri is whitelisted in Autentico's config.

EFFECTIVE_URL=$(curl -G -s -o /dev/null -w "%{url_effective}\n" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=el_autentico_!" \
  --data-urlencode "redirect_uri=https://your-client-app.com/callback" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=xyz123abc" \
  http://localhost:9999/oauth2/authorize)

echo "Open this URL in your browser: ${EFFECTIVE_URL}"
# Example for macOS: open "${EFFECTIVE_URL}"
```

### Token Exchange

After successful authentication, the user is redirected back to your `redirect_uri` with an authorization `code`. Exchange this code for tokens at the `/oauth2/token` endpoint.

**Using HTTP Basic Auth (client_secret_basic - Recommended):**

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u "your_client_id:your_client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=your_received_authorization_code" \
  -d "redirect_uri=https://your-client-app.com/callback"
```

**Using Form Parameters (client_secret_post):**

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=your_received_authorization_code" \
  -d "redirect_uri=https://your-client-app.com/callback" \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret"
```

**For Public Clients (no secret required):**

```bash
curl -X POST http://localhost:9999/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=your_received_authorization_code" \
  -d "redirect_uri=https://your-client-app.com/callback" \
  -d "client_id=your_client_id"
```

A successful response will contain `access_token`, `id_token`, `refresh_token`, `token_type`, and `expires_in`.

---

## Security Considerations

As an Identity Provider, Autentico is a critical trust boundary. The following practices apply:

- **HTTPS**: Always deploy behind a reverse proxy with TLS in production. An IdP must never serve tokens over plaintext.
- **Secure Cookies**: Set `AuthRefreshTokenAsSecureCookie` and `AuthCSRFSecureCookie` to `true` when using HTTPS.
- **CSRF Protection**: `gorilla/csrf` protects interactive endpoints (login form). Use a strong, unique 32-byte `AuthCSRFProtectionSecretKey`.
- **Redirect URI Validation**: Strictly validates `redirect_uri` against registered client URIs to prevent open redirector attacks.
- **Client Authentication**: Confidential relying parties authenticate via client secret (HTTP Basic Auth or form parameters). Secrets are bcrypt-hashed at rest.
- **Strong Secret Keys**: All configured secrets (`AuthAccessTokenSecret`, `AuthRefreshTokenSecret`, `AuthCSRFProtectionSecretKey`) must be cryptographically strong.
- **RS256 Token Signing**: Tokens are signed with RSA private keys. Only the IdP holds the private key; relying parties verify using the public JWK Set.
- **Input Validation**: Usernames and passwords are validated according to configured length and format rules.

---

## Testing

Autentico maintains comprehensive test coverage with **336+ test functions** across unit, integration, and end-to-end tests.

### Test Coverage

![Test Coverage](https://img.shields.io/badge/coverage-78.1%25-green.svg)
![Test Count](https://img.shields.io/badge/tests-336-blue.svg)
![Packages Tested](https://img.shields.io/badge/packages-15-lightgrey.svg)

| Package          | Coverage | Test Count | Focus Area               |
| ---------------- | -------- | ---------- | ------------------------ |
| `pkg/config`     | 100.0%   | 8          | Configuration management |
| `pkg/model`      | 100.0%   | 6          | Data validation          |
| `pkg/wellknown`  | 100.0%   | 4          | OIDC discovery           |
| `pkg/idpsession` | 96.3%    | 15         | Session management       |
| `pkg/jwtutil`    | 95.2%    | 10         | JWT validation           |
| `pkg/authorize`  | 93.3%    | 13         | Authorization flow       |
| `pkg/middleware` | 93.4%    | 21         | Security middleware      |
| `pkg/user`       | 92.3%    | 46         | User management          |
| `pkg/auth_code`  | 90.9%    | 16         | Authorization codes      |
| `pkg/session`    | 90.7%    | 13         | Session lifecycle        |
| `pkg/introspect` | 89.4%    | 13         | Token introspection      |

### Running Tests

```bash
# Run all tests with coverage
make test
# Or: go test -p 1 -v ./...

# Generate coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Run specific test suites
go test ./pkg/token/... -v          # Token handling tests
go test ./tests/e2e/... -v          # End-to-end integration tests
go test ./pkg/middleware/... -v     # Security middleware tests
```

### Test Categories

**Unit Tests** (280+ tests): Comprehensive coverage of individual components

- **Handler tests**: API endpoint behavior, error handling, validation
- **Model tests**: Data structure validation, serialization/deserialization
- **Service tests**: Business logic, authentication flows
- **Utility tests**: Helper functions, middleware components

**Integration Tests** (40+ tests): Cross-component functionality

- **Authorization flow**: Complete OAuth2/OIDC workflows
- **Token lifecycle**: Issuance, refresh, revocation, introspection
- **Client authentication**: Multiple auth methods and grant types
- **Session management**: Login, logout, idle timeout handling

**End-to-End Tests** (16+ tests): Full system workflows

- **Authentication flows**: Real browser-like interactions
- **Token exchanges**: Complete authorization code flow
- **Security validations**: CSRF, CORS, input validation
- **Performance tests**: Load testing critical endpoints

### Test Quality Assurance

Tests cover IdP-critical functionality including:

- **Security**: Token signing, validation, CSRF protection, input sanitization
- **Standards Compliance**: OAuth2/OIDC specification adherence
- **Error Handling**: Graceful degradation, proper error responses
- **Edge Cases**: Expired tokens, invalid inputs, malformed requests
- **Performance**: Response times, memory usage, concurrent access

---

## Contributing

Contributions are welcome and appreciated! Please follow these general guidelines:

1.  **Fork the repository** on GitHub.
2.  **Create a new feature branch** for your changes (e.g., `git checkout -b feature/my-new-feature`).
3.  **Make your changes** and ensure they adhere to Go best practices and project style.
4.  **Add or update tests** for your changes. Ensure all tests pass (`make test`).
5.  **Commit your changes** with clear and descriptive commit messages.
6.  **Push your branch** to your fork (`git push origin feature/my-new-feature`).
7.  **Submit a pull request** to the main Autentico repository.

Please open an issue to discuss significant changes or new features before starting work.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file in the repository for the full license text.
