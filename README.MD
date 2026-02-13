# Autentico - OIDC Identity Provider

[![Test Coverage](https://img.shields.io/badge/coverage-78.1%25-green.svg)](https://github.com/eugenioenko/autentico)
[![Tests](https://img.shields.io/badge/tests-358-blue.svg)](https://github.com/eugenioenko/autentico)
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
- [Deployment & Operations](#deployment--operations)
- [Troubleshooting & Operations](#troubleshooting--operations)
- [Admin UI](#admin-ui)
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
- **Authorization Code Flow with PKCE**: Implements the recommended secure flow for web and mobile applications, with Proof Key for Code Exchange (RFC 7636) support for public clients.
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

### Project Structure

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

### Design Philosophy
Auténtico prioritizes operational simplicity and deployment autonomy as first-class architectural concerns. The design deliberately minimizes external dependencies and infrastructure complexity to reduce the operational surface area and eliminate entire classes of failure modes. This is not a prototype—it is production-grade infrastructure built with the understanding that the highest leverage engineering decisions are those that remove complexity rather than accommodate it prematurely.

### Why SQLite
SQLite is an architectural choice, not a constraint. For identity workloads at this scale, SQLite's performance characteristics—handling tens of thousands of concurrent reads with single-digit millisecond latency—far exceed typical requirements. The embedded database eliminates connection pooling, network partitions, credential rotation, and distributed transaction complexity. It collapses the deployment model to a single binary with no external runtime dependencies, which fundamentally changes the operational contract: no orchestration layers, no managed services, no stateful infrastructure to provision. When load characteristics eventually justify migration, that decision comes with the resources and operational maturity to execute it correctly. Until then, the engineering velocity gained from eliminating accidental complexity is substantial.

**Performance Benchmarks** (2024 M1 MacBook Pro, 16GB RAM):
- Token issuance: ~2,500 tokens/sec/core
- Authorization code validation: < 5ms p99
- Session lookup: < 2ms p95
- Database size: ~50KB per 1,000 users (excluding audit logs)
- Memory footprint: ~45MB baseline, ~120MB under load (10k concurrent sessions)

SQLite's write serialization is the eventual bottleneck. At ~500 writes/sec sustained, consider write batching or migration to PostgreSQL. For read-heavy IdP workloads (typical ratio: 100:1 reads:writes), this threshold represents approximately 50,000 logins/hour.

### Why RS256 over HS256
Symmetric signing algorithms like HS256 require any party that verifies a token to also hold the secret used to sign it, which creates a secret distribution problem as the number of relying parties grows. RS256 allows Auténtico to hold the private key exclusively while any relying party can verify tokens independently using the public JWK Set exposed at /oauth2/certs. This is the correct architecture for an IdP regardless of scale.

## On ROPC Support
The Resource Owner Password Credentials grant is deprecated in OAuth 2.1 and not recommended for new integrations. It is supported here deliberately, because omitting it would break backward compatibility with legacy clients, older SDKs, and internal tooling that existing projects may already depend on. If you are building something new, use the Authorization Code flow instead.
(ROPC support is planned to be feature flagged allowing to disable it)

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

4.  **Initialize the admin user and admin client:**

    On a fresh install there are no users. Use the `init` command to bootstrap the admin user and the Admin UI client:

    ```bash
    ./autentico init --email="admin@example.com" --password="YourSecurePassword"
    ```

    This creates an admin account and the Admin UI client. The admin account can then be used to register OAuth2 clients via `/oauth2/register` and create additional users via `/user`.

5.  **Run the application:**
    ```bash
    make run
    # Or directly:
    # ./autentico start
    ```
    The server will start, by default, on `http://localhost:9999`.

---

## Configuration

Application settings are loaded from `autentico.json` at startup. Create this file in the project root directory to override default values. Only the fields you want to change need to be specified; all others will use defaults.

**Example `autentico.json`:**

```json
{
  "appDomain": "myapp.example.com",
  "appPort": "9999",
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
| `dbFilePath`                      | The file path for the SQLite database.                                            | `./db/autentico.db`                 |
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
| `authAccountLockoutMaxAttempts`   | Number of failed login attempts before account is locked. Set to `0` to disable.  | `5`                            |
| `authAccountLockoutDuration`      | Duration of account lockout after max failed attempts (e.g., `15m`, `1h`).        | `15m`                          |
| `swaggerPort`                     | Port on which the Swagger documentation server runs.                              | `8888`                         |

### Login Page Theming

The login page can be customized via the `theme` object in `autentico.json`.

**Theme Options:**

| Field              | Description                                                    | Default                                                              |
|--------------------|----------------------------------------------------------------|----------------------------------------------------------------------|
| `themeTitle`       | Page title shown in browser tab                                | `Autentico Login`                                                    |
| `themeLogoUrl`     | URL to a logo image (replaces default SVG)                     | _(default SVG logo)_                                                 |
| `themeFontUrl`     | URL to load a web font (e.g., Google Fonts)                    | Fira Sans from Google Fonts                                          |
| `themeFontFamily`  | CSS `font-family` value                                        | `"Fira Sans", "Helvetica Neue", Helvetica, Arial, sans-serif`       |
| `themeCssFile`     | Path to an external CSS file (read once at startup)            | _(none)_                                                             |
| `themeCssInline`   | Inline CSS string (overrides `themeCssFile` if both are set)   | _(none)_                                                             |

**Example configuration:**

```json
{
  "theme": {
    "themeTitle": "My App Login",
    "themeLogoUrl": "https://example.com/logo.png",
    "themeFontUrl": "https://fonts.googleapis.com/css2?family=Inter:wght@300;700&display=swap",
    "themeFontFamily": "\"Inter\", sans-serif",
    "themeCssFile": "/etc/autentico/custom-theme.css"
  }
}
```

**Available CSS Variables:**

Override these in your custom CSS file or `themeCssInline`:

```css
:root {
  /* Typography */
  --font-size: 16px;
  --font-family: "Fira Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;

  /* Colors - Light Mode */
  --color-primary: #2e5bff;
  --color-accent: #188060;
  --color-danger: #ff4848;
  --color-text: #0f0f0f;
  --color-inverse: #ffffff;
  --color-background: #f1f1f1;
  --color-card: #ffffff;
  --color-border: #696969;

  /* Layout */
  --border-radius: 2px;
  --form-width: 380px;
  --form-padding: 30px;
  --form-gap: 16px;
  --form-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);

  /* Logo */
  --logo-size: 96px;
  --logo-margin: 16px 0 32px 0;
  --logo-padding: 16px;

  /* Elements */
  --input-padding: 10px;
  --button-padding: 10px;
  --button-margin-top: 16px;
  --h1-font-size: 2rem;
  --label-padding-bottom: 4px;
}

/* Dark mode: override color variables */
@media (prefers-color-scheme: dark) {
  :root {
    --color-primary: #2e5bff;
    --color-accent: #188060;
    --color-danger: #d60b0b;
    --color-text: #e7e7e7;
    --color-inverse: #e7e7e7;
    --color-background: #0f0f0f;
    --color-card: #1e1f22;
    --color-border: #cccccc;
  }
}
```

---

## API Documentation

Autentico provides comprehensive API documentation:

1.  **Static HTML Documentation**:
    A pre-generated, detailed HTML API reference is available.
    - [Autentico API Documentation (GitHub Pages)](https://eugenioenko.github.io/autentico/index.html)
    - You can also find this at `/docs/index.html` in the repository.

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

- **Authorization Code (with PKCE)** — The recommended flow for web and native applications. The IdP authenticates the user, issues an authorization code, and the relying party exchanges it for ID + access tokens. PKCE (RFC 7636) is supported for public clients using S256 or plain challenge methods.
- **Resource Owner Password Credentials** — Direct credential exchange. Provided for trusted or legacy clients; not recommended for new applications.
- **Refresh Token** — Obtain new access tokens without re-authenticating the user.

---

## Client Interaction Examples

Autentico supports dynamic client registration via the `/oauth2/register` API. Admin users can register relying parties (OAuth2 clients), which are then validated during authorization and token flows.

### Register an OAuth2 Client (Admin Only)

Register a new client application. This requires an admin user's access token:

```bash
# First, obtain an admin access token (admin user must exist)
ADMIN_TOKEN=$(curl -s -X POST http://localhost:9999/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin@example.com&password=AdminPassword123!" \
  | jq -r '.access_token')

# Register a new confidential client
curl -X POST http://localhost:9999/oauth2/register \
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
curl -X POST http://localhost:9999/oauth2/register \
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

**Using JavaScript (with PKCE):**

```javascript
// Generate PKCE code_verifier and code_challenge
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);
// Store codeVerifier for the token exchange step
sessionStorage.setItem("code_verifier", codeVerifier);

const authServerUrl = "http://localhost:9999/oauth2/authorize";
const params = new URLSearchParams({
  response_type: "code",
  redirect_uri: "https://your-client-app.com/callback",
  scope: "openid profile email",
  state: "callback_state",
  nonce: crypto.randomUUID(),
  code_challenge: codeChallenge,
  code_challenge_method: "S256",
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
  --data-urlencode "nonce=$(uuidgen)" \
  http://localhost:9999/oauth2/authorize)

echo "Open this URL in your browser: ${EFFECTIVE_URL}"
# Example for macOS: open "${EFFECTIVE_URL}"
```

### Token Exchange

After successful authentication, the user is redirected back to your `redirect_uri` with an authorization `code`. Exchange this code for tokens at the `/oauth2/token` endpoint.

**Using HTTP Basic Auth (client_secret_basic - Recommended):**

```bash
curl -X POST http://localhost:9999/oauth2/token \
  -u "your_client_id:your_client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=your_received_authorization_code" \
  -d "redirect_uri=https://your-client-app.com/callback"
```

**Using Form Parameters (client_secret_post):**

```bash
curl -X POST http://localhost:9999/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=your_received_authorization_code" \
  -d "redirect_uri=https://your-client-app.com/callback" \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret"
```

**For Public Clients with PKCE (recommended):**

```bash
curl -X POST http://localhost:9999/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=your_received_authorization_code" \
  -d "redirect_uri=https://your-client-app.com/callback" \
  -d "client_id=your_client_id" \
  -d "code_verifier=your_stored_code_verifier"
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

## Deployment & Operations

### Production Deployment Patterns

Autentico's single-binary architecture supports multiple deployment models:

**Container Deployment** (Recommended for orchestrated environments):
```dockerfile
FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY autentico /usr/local/bin/
COPY autentico.json /etc/autentico/
VOLUME ["/data"]
EXPOSE 9999
CMD ["autentico", "start"]
```


**Reverse Proxy Configuration** (nginx example):
```nginx
upstream autentico {
    server 127.0.0.1:9999;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;
    
    ssl_certificate /etc/ssl/certs/auth.example.com.crt;
    ssl_certificate_key /etc/ssl/private/auth.example.com.key;
    
    location / {
        proxy_pass http://autentico;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Observability

Autentico logs structured events to stdout. Recommended observability stack:

- **Metrics**: Expose `/metrics` endpoint for Prometheus scraping (memory, request rates, token issuance)
- **Logging**: JSON-structured logs with correlation IDs for distributed tracing
- **Alerting**: Monitor failed authentication attempts, token validation failures, session expiry rates
- **Key SLIs**: 
  - Token issuance latency (p95 < 100ms)
  - Authorization code exchange success rate (> 99.9%)
  - Session validation latency (p99 < 50ms)

### Backup & Recovery

SQLite database backup strategies:

```bash
# Hot backup using SQLite's backup API
sqlite3 /data/autentico.db ".backup /backup/autentico-$(date +%Y%m%d-%H%M%S).db"

# Incremental backups using WAL mode
sqlite3 /data/autentico.db "PRAGMA journal_mode=WAL;"
# WAL files can be backed up separately while database is running
```

Recovery time objective (RTO): < 5 minutes for single-instance deployments.

### Migration Path to Distributed Database

When SQLite performance becomes constrained (typically > 100k daily active users), migration path:

1. **Read Replica Pattern**: Add PostgreSQL as async replica for read queries
2. **Dual-Write Phase**: Write to both SQLite and PostgreSQL with SQLite as source of truth
3. **Cutover**: Switch reads to PostgreSQL, validate consistency
4. **Finalize**: Remove SQLite dependency

The codebase abstracts database operations through the `pkg/db` interface, allowing backend swaps without rewriting business logic.

### High Availability Considerations

For HA deployments:

- **Stateless Design**: All session state in database; instances are interchangeable
- **Health Checks**: `GET /.well-known/openid-configuration` as liveness probe
- **Graceful Shutdown**: SIGTERM handling ensures in-flight requests complete
- **Database Locking**: SQLite WAL mode supports concurrent readers; single writer sufficient for typical IdP workloads

---

## Admin UI

Autentico includes a built-in admin dashboard served at `/admin/`. It requires an admin user account to log in.

### Building the Admin UI

The admin UI is a React application embedded into the Go binary at build time. To build it:

```bash
# Build the admin UI and copy it into the Go embed directory
make admin-ui-build

# Or build everything (admin UI + Go binary) in one step
make build-all
```

After building, the admin UI is available at `http://localhost:9999/admin/` when the server is running.

### Development Mode

For frontend development with hot-reload:

```bash
# Start the Go server
make run

# In another terminal, start the Vite dev server
cd admin-ui && pnpm dev
```

The dev server runs at `http://localhost:5173/admin/` and proxies API requests to the Go server on port 9999.

---

## Testing

Autentico maintains comprehensive test coverage with **358+ test functions** across unit, integration, and end-to-end tests.

### Test Coverage

![Test Coverage](https://img.shields.io/badge/coverage-78.1%25-green.svg)
![Test Count](https://img.shields.io/badge/tests-358-blue.svg)
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

## Troubleshooting & Operations

### Common Operational Issues

**Token Validation Failures**
```bash
# Verify JWK Set is accessible
curl http://localhost:9999/oauth2/certs

# Check private key permissions
ls -la ./db/private_key.pem  # Should be 600

# Validate token signature locally
# Use jwt.io or jwt-cli to decode and verify against public key
```

**Database Lock Timeouts**
```bash
# Check for long-running transactions
sqlite3 /data/autentico.db "PRAGMA wal_checkpoint(FULL);"

# Verify WAL mode is enabled
sqlite3 /data/autentico.db "PRAGMA journal_mode;"
# Expected output: wal
```

**Session Exhaustion**
- Monitor active session count in database
- Default idle timeout: 30 minutes
- Implement session cleanup cron: `DELETE FROM sessions WHERE updated_at < datetime('now', '-30 minutes')`

**Memory Leaks**
- Watch RSS over time: `ps aux | grep autentico`
- Check for orphaned goroutines: enable pprof endpoint in production builds
- Expected steady-state: 45-120MB depending on active sessions

### Performance Tuning

**SQLite Optimizations**:
```sql
-- Enable WAL mode for better concurrency
PRAGMA journal_mode=WAL;

-- Increase cache size (default 2MB, increase to 64MB)
PRAGMA cache_size=-64000;

-- Synchronous mode for performance vs. durability tradeoff
PRAGMA synchronous=NORMAL;  -- FULL for maximum durability
```

**Go Runtime Tuning**:
```bash
# In containerized environments, explicitly set GOMAXPROCS to match CPU limits
# Go may not auto-detect container CPU quotas correctly
GOMAXPROCS=4 ./autentico start

# Adjust GC target percentage for memory/CPU tradeoff
GOGC=200 ./autentico start  # Less frequent GC, higher memory usage, lower CPU overhead

# Note: SQLite write serialization is the bottleneck, not CPU parallelism
# GOMAXPROCS helps with concurrent request handling and cryptographic operations,
# but won't increase write throughput beyond SQLite's single-writer constraint
```

### Security Incident Response

**Compromised Client Secret**:
1. Rotate secret via `PUT /oauth2/register/{client_id}`
2. Revoke all tokens for affected client: `DELETE FROM tokens WHERE client_id = ?`
3. Force re-authentication: `DELETE FROM sessions WHERE client_id = ?`

**Suspected Token Leakage**:
1. Rotate signing keys (requires downtime or dual-key validation period)
2. Revoke affected tokens via `/oauth2/revoke`
3. Monitor for unusual token introspection patterns

**Brute Force Attack**:
- Rate limiting implemented at reverse proxy layer (recommended)
- Monitor failed login attempts: `grep 'authentication failed' /var/log/autentico.log | wc -l`
- Consider CAPTCHA integration for repeated failures


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
