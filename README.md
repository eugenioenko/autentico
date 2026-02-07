# Autentico

Autentico is a lightweight, self-contained OpenID Connect (OIDC) Identity Provider built with Go and SQLite. It implements the core OAuth 2.0 and OIDC specifications, providing authentication and token management with minimal dependencies and zero external infrastructure requirements.

## Features

- **OpenID Connect Discovery** - `/.well-known/openid-configuration` and JWKS endpoints
- **Authorization Code Flow** - Standard OIDC authorization code grant with login UI
- **Password Grant** - Resource Owner Password Credentials for trusted clients
- **Refresh Token Grant** - Token renewal without re-authentication
- **Token Introspection** - RFC 7662 token introspection endpoint
- **Token Revocation** - Revoke access and refresh tokens
- **UserInfo Endpoint** - OIDC UserInfo for retrieving authenticated user claims
- **Client Registration** - Dynamic client registration with admin-only CRUD management
- **Session Management** - Server-side sessions with IdP session cookies and idle timeout
- **JWK Support** - RS256-signed JWTs with published JSON Web Key Sets
- **CSRF Protection** - Built-in CSRF middleware for browser-based flows
- **CORS Support** - Configurable Cross-Origin Resource Sharing
- **Swagger / OpenAPI** - Auto-generated API documentation

## Quick Start

### Prerequisites

- Go 1.23+
- OpenSSL (for RSA key generation)

### Setup

```bash
# Clone the repository
git clone https://github.com/eugenioenko/autentico.git
cd autentico

# Generate the RSA private key used for signing JWTs
make generate-key

# Run the server
make run
```

The server starts at `http://localhost:9999` by default. The OIDC discovery document is available at:

```
http://localhost:9999/.well-known/openid-configuration
```

### Docker

```bash
# Build the image
make docker-build

# Or use docker compose
make docker-compose
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery document |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |
| GET | `/oauth2/authorize` | Authorization endpoint (renders login page) |
| POST | `/oauth2/login` | Login form submission (creates authorization code) |
| POST | `/oauth2/token` | Token endpoint (code exchange, password grant, refresh) |
| POST | `/oauth2/revoke` | Token revocation |
| POST | `/oauth2/introspect` | Token introspection |
| GET | `/oauth2/userinfo` | UserInfo endpoint |
| POST | `/oauth2/logout` | Session logout |
| POST | `/oauth2/register` | Register a new client (admin) |
| GET | `/oauth2/register` | List all clients (admin) |
| GET | `/oauth2/register/{client_id}` | Get client details (admin) |
| PUT | `/oauth2/register/{client_id}` | Update a client (admin) |
| DELETE | `/oauth2/register/{client_id}` | Deactivate a client (admin) |
| POST | `/user` | Create a new user |

Keycloak-compatible aliases are also available:

| Endpoint | Alias for |
|----------|-----------|
| `/oauth2/protocol/openid-connect/token` | `/oauth2/token` |
| `/oauth2/protocol/openid-connect/userinfo` | `/oauth2/userinfo` |

## Configuration

Autentico is configured through `autentico.json` at the project root. All fields are optional; defaults are applied for any missing values.

### Application Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `appDomain` | string | `"localhost"` | Domain name used for cookies |
| `appHost` | string | `"localhost:9999"` | Host and port the server binds to |
| `appPort` | string | `"9999"` | Port the server listens on |
| `appUrl` | string | `"http://localhost:9999"` | Public-facing base URL of the server |
| `appEnableCORS` | bool | `true` | Enable CORS middleware |
| `appOAuthPath` | string | `"/oauth2"` | Base path prefix for all OAuth2/OIDC endpoints |
| `appAuthIssuer` | string | `"http://localhost:9999/oauth2"` | `iss` claim value in issued tokens and discovery document |

### Database Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dbFilePath` | string | `"./db/auth.db"` | Path to the SQLite database file |

### Token Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `authAccessTokenSecret` | string | `"your-secret-here"` | Secret used for access token signing |
| `authAccessTokenExpiration` | duration | `"15m"` | Access token lifetime (Go duration format) |
| `authRefreshTokenSecret` | string | `"your-secret-here"` | Secret used for refresh token signing |
| `authRefreshTokenExpiration` | duration | `"720h"` | Refresh token lifetime (Go duration format, default 30 days) |
| `authRefreshTokenCookieName` | string | `"autentico_refresh_token"` | Cookie name when refresh token is sent as a secure cookie |
| `authRefreshTokenAsSecureCookie` | bool | `false` | Send refresh token as an HttpOnly secure cookie instead of in the response body |
| `authAccessTokenAudience` | []string | `["el_autentico_!"]` | List of allowed `aud` claim values for access tokens |
| `authAuthorizationCodeExpiration` | duration | `"10m"` | Authorization code lifetime |
| `authPrivateKeyFile` | string | `"./db/private_key.pem"` | Path to the RSA private key (PEM) used for RS256 JWT signing |
| `authJwkCertKeyID` | string | `"autentico-key-1"` | `kid` (Key ID) published in the JWKS endpoint |

### Client Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `authDefaultClientID` | string | `"el_autentico_!"` | Default client ID used when no client is specified |
| `authAllowedRedirectURIs` | []string | `[]` | Allowed redirect URIs for the authorization code flow |

### Session Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `authSsoSessionIdleTimeout` | duration | `"0"` | IdP session idle timeout. `"0"` disables idle timeout |
| `authIdpSessionCookieName` | string | `"autentico_idp_session"` | Cookie name for the IdP session |
| `authIdpSessionSecureCookie` | bool | `false` | Set the `Secure` flag on the IdP session cookie |

### Security Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `authCSRFProtectionSecretKey` | string | `"your-secret-here"` | Secret key for CSRF token generation |
| `authCSRFSecureCookie` | bool | `false` | Set the `Secure` flag on the CSRF cookie |

### Role Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `authRealmAccessRoles` | []string | `[]` | Roles included in the `realm_access` claim of issued tokens |

### Validation Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `validationMinUsernameLength` | int | `4` | Minimum username length |
| `validationMaxUsernameLength` | int | `64` | Maximum username length |
| `validationMinPasswordLength` | int | `6` | Minimum password length |
| `validationMaxPasswordLength` | int | `64` | Maximum password length |
| `validationUsernameIsEmail` | bool | `true` | Require usernames to be valid email addresses |
| `validationEmailRequired` | bool | `false` | Require an email address during user creation |

### Swagger Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `swaggerPort` | string | `"8888"` | Port for the Swagger UI documentation server |

## Development

```bash
# Build the binary
make build

# Run tests (sequential to avoid SQLite conflicts)
make test

# Run a specific package's tests
go test ./pkg/token/...

# Run a single test
go test -run TestCreateUser ./pkg/user/...

# Format code
make fmt

# Lint (requires golangci-lint)
make lint

# Generate Swagger docs
make generate-docs

# Serve Swagger UI
make docs
```

## License

See [LICENSE](LICENSE) for details.
