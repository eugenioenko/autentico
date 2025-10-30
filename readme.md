# 🔐 Autentico OIDC

[![Go Version](https://img.shields.io/badge/Go-1.21-blue)](https://golang.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/eugenioenko/autentico/actions)
[![License](https://img.shields.io/badge/license-MIT-blue)](/home/enko/Documents/autentico/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/eugenioenko/autentico)](https://goreportcard.com/report/github.com/eugenioenko/autentico)

**Auténtico is an OpenID Connect (OIDC) authentication server built with Go, designed for developers seeking a lightweight, secure, and embeddable solution for modern identity management. It leverages SQLite for data persistence, ensuring easy integration and deployment.**

---

## Table of Contents

- [🔐 Autentico OIDC](#-autentico-oidc)
  - [Table of Contents](#table-of-contents)
  - [✨ Features](#-features)
  - [🛠️ Tech Stack](#️-tech-stack)
  - [🏗️ Architecture Overview](#️-architecture-overview)
  - [🚀 Getting Started](#-getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation \& Running](#installation--running)
  - [⚙️ Configuration](#️-configuration)
  - [📜 API Documentation](#-api-documentation)
  - [🔐 Endpoints](#-endpoints)
    - [OpenID Connect Endpoints](#openid-connect-endpoints)
    - [Well-Known Configuration](#well-known-configuration)
    - [User Management](#user-management)
  - [🧪 Supported Flows](#-supported-flows)
  - [🧑‍💻 Client Interaction Examples](#-client-interaction-examples)
    - [Register a User](#register-a-user)
    - [Authorization Request](#authorization-request)
    - [Token Exchange](#token-exchange)
  - [🛡️ Security Considerations](#️-security-considerations)
  - [🧪 Testing](#-testing)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)

---

## ✨ Features

Autentico provides a comprehensive suite of features for identity and access management:

- **OIDC & OAuth 2.0 Compliance**: Adheres to industry-standard protocols for authentication and authorization.
- **Authorization Code Flow**: Implements the recommended secure flow for web and mobile applications.
- **Refresh Token Support**: Allows clients to obtain new access tokens without re-authenticating the user.
- **Token Introspection & Revocation**: Provides endpoints for validating and invalidating tokens (RFC 7009, RFC 7662).
- **Secure Session Management**: Ensures robust handling of user sessions.
- **Lightweight and Embeddable**: Built with Go and SQLite, making it easy to integrate into various environments.
- **CSRF Protection**: Utilizes `gorilla/csrf` for protection against Cross-Site Request Forgery attacks on relevant endpoints.
- **Modular Design**: Organized into logical packages for clear separation of concerns (e.g., `token`, `user`, `session`).
- **Comprehensive API Documentation**: Includes HTML API documentation and Swagger/OpenAPI specifications.

---

## 🛠️ Tech Stack

Autentico is built with a focus on performance, security, and maintainability:

- **Go (Golang)**: Chosen for its performance, concurrency features, and suitability for building robust backend services. The standard library and strong type system contribute to a reliable codebase.
- **SQLite**: Selected as the database backend for its simplicity, embeddability, and ease of setup. Ideal for single-server deployments or applications where a full-fledged database server is an overkill.
- **Gorilla Toolkit**: Specifically `gorilla/csrf` for CSRF protection, known for their robustness and wide adoption in the Go community.
- **Testify**: Used for assertions and mocking in unit and integration tests, facilitating comprehensive test coverage.
- **Swagger/OpenAPI**: For API design, documentation, and generation, ensuring clear and usable API contracts.

---

## 🏗️ Architecture Overview

Autentico follows a modular, layered architecture to promote separation of concerns and maintainability. Key components reside within the `pkg/` directory:

- **`config`**: Manages application configuration, loaded at startup.
- **`db`**: Handles database interactions, abstracting SQLite operations.
- **`handler` (within feature packages like `authorize`, `token`, `userinfo`)**: Contains HTTP handlers responsible for request/response processing.
- **`service` (within feature packages)**: Implements the core business logic for each feature.
- **`model`**: Defines data structures and request/response DTOs.
- **`middleware`**: Provides common HTTP middleware like logging, CORS, and CSRF protection.
- **`session`**: Manages user session lifecycle and persistence.
- **`token`**: Handles JWT generation, validation, introspection, and revocation.
- **`user`**: Manages user creation, authentication, and data.
- **`wellknown`**: Serves the OIDC discovery document.

The `main.go` file initializes the configuration, database, and routes, and starts the HTTP server. Static assets like the login page are served from the `view/` directory.

---

## 🚀 Getting Started

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

3.  **Generate a private key certificate (optional for token signing):**
If certificate doesn't exist, the server will auto generate one

    ```bash
    openssl genpkey -algorithm RSA -out ./db/private_key.pem -pkeyopt rsa_keygen_bits:2048
    ```

4.  **Run the application:**
    ```bash
    make run
    # Or directly:
    # ./autentico
    ```
    The server will start, by default, on `http://localhost:9999`.

---

## ⚙️ Configuration

Application settings are managed in `pkg/config/config.go`. Key configuration options include:

| **Setting**                       | **Description**                                                                   | **Default Value**         |
| --------------------------------- | --------------------------------------------------------------------------------- | ------------------------- |
| `AppDomain`                       | The domain name of the application.                                               | `localhost`               |
| `AppPort`                         | The port on which the application runs.                                           | `9999`                    |
| `AppOAuthPath`                    | The base path for OAuth2 endpoints (e.g., `/oauth2`).                             | `/oauth2`                 |
| `DbFilePath`                      | The file path for the SQLite database.                                            | `./db/auth.db`            |
| `AuthAccessTokenSecret`           | Secret key used to sign access tokens. **Change this in production!**             | `your-secret-here`        |
| `AuthAccessTokenExpiration`       | Duration for which access tokens are valid (e.g., `15m`, `1h`).                   | `15m`                     |
| `AuthRefreshTokenSecret`          | Secret key used to sign refresh tokens. **Change this in production!**            | `your-secret-here`        |
| `AuthRefreshTokenExpiration`      | Duration for which refresh tokens are valid (e.g., `7d`, `30d`).                  | `30d`                     |
| `AuthRefreshTokenCookieName`      | Name of the cookie storing the refresh token.                                     | `autentico_refresh_token` |
| `AuthRefreshTokenAsSecureCookie`  | If `true`, sets the Secure flag on the refresh token cookie (requires HTTPS).     | `false`                   |
| `AuthDefaultClientID`             | Default client ID for the application if dynamic client registration is not used. | `el_autentico_!`          |
| `AuthAuthorizationCodeExpiration` | Duration for which authorization codes are valid.                                 | `10m`                     |
| `AuthAllowedRedirectURIs`         | A list of allowed redirect URIs for OAuth2 client flows.                          | `[]`                      |
| `AuthCSRFProtectionSecretKey`     | 32-byte secret key for CSRF protection. **Generate and set this in production!**  | `your-secret-here`        |
| `AuthCSRFSecureCookie`            | If `true`, sets the Secure flag on the CSRF cookie (requires HTTPS).              | `false`                   |
| `ValidationMinUsernameLength`     | Minimum length for usernames.                                                     | `4`                       |
| `ValidationMaxUsernameLength`     | Maximum length for usernames.                                                     | `64`                      |
| `ValidationMinPasswordLength`     | Minimum length for passwords.                                                     | `6`                       |
| `ValidationMaxPasswordLength`     | Maximum length for passwords.                                                     | `64`                      |
| `ValidationUsernameIsEmail`       | If `true`, usernames must be valid email addresses.                               | `true`                    |
| `ValidationEmailRequired`         | If `true`, email is required for user registration.                               | `false`                   |
| `SwaggerPort`                     | Port on which the Swagger documentation server runs.                              | `8888`                    |

---

## 📜 API Documentation

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

## 🔐 Endpoints

### OpenID Connect Endpoints

All OAuth/OIDC endpoints are prefixed by `AppOAuthPath` (default: `/oauth2`).

- **Authorization**: `GET /oauth2/authorize`
  - Initiates the OIDC authentication and authorization flow.
- **Token**: `POST /oauth2/token`
  - Exchanges an authorization code (or refresh token) for an access token (and optionally a new refresh token).
- **User Info**: `GET /oauth2/userinfo`
  - Retrieves claims about the authenticated user. Requires a valid access token.
- **Token Revocation**: `POST /oauth2/revoke` (RFC 7009)
  - Revokes an access token or refresh token.
- **Token Introspection**: `POST /oauth2/introspect` (RFC 7662)
  - Checks the validity and metadata of an access token or refresh token.
- **Logout**: `POST /oauth2/logout`
  - Logs out the user by invalidating their session.

### Well-Known Configuration

- **OIDC Discovery**: `GET /.well-known/openid-configuration`
  - Provides metadata about the OIDC provider's configuration, allowing clients to dynamically discover endpoints and capabilities.

### User Management

- **Create User**: `POST /users/create`
  - Registers a new user in the system.

---

## 🧪 Supported Flows

Autentico currently supports the following OAuth 2.0 grant types:

- **Authorization Code Flow**:
  - The primary and most secure flow for web applications and native/mobile apps.
- **Resource Owner Password Credentials Flow**:
  - Allows exchanging a user's credentials directly for an access token.
  - **Note**: This flow is generally discouraged for new applications due to security risks but is provided for legacy compatibility or specific trusted client scenarios.
- **Refresh Token Grant**:
  - Used to obtain a new access token using a refresh token.

---

## 🧑‍💻 Client Interaction Examples

Client registration is currently manual. You must add your client application's redirect URI(s) to the `AuthAllowedRedirectURIs` list in the configuration (`pkg/config/config.go`).

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

After successful authentication, the user is redirected back to your `redirect_uri` with an authorization `code`. Exchange this code for tokens at the `/oauth2/token` endpoint:

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

## 🛡️ Security Considerations

Security is a primary concern for an authentication server. Autentico incorporates several security practices:

- **HTTPS**: Always deploy Autentico behind a reverse proxy configured with HTTPS in production environments to protect data in transit.
- **Secure Cookies**: Configure `AuthRefreshTokenAsSecureCookie` and `AuthCSRFSecureCookie` to `true` when using HTTPS. This ensures these cookies are only transmitted over secure connections.
- **CSRF Protection**: `gorilla/csrf` is used for endpoints susceptible to CSRF attacks (e.g., login form submissions). Ensure `AuthCSRFProtectionSecretKey` is a strong, unique 32-byte key.
- **Redirect URI Validation**: Autentico strictly validates `redirect_uri` parameters against a pre-configured whitelist (`AuthAllowedRedirectURIs`) to prevent open redirector vulnerabilities.
- **Strong Secret Keys**: Ensure all configured secrets (`AuthAccessTokenSecret`, `AuthRefreshTokenSecret`, `AuthCSRFProtectionSecretKey`) are cryptographically strong and kept confidential.
- **Input Validation**: User inputs (usernames, passwords) are validated according to configured length and format rules.
- **Regular Dependency Updates**: Keep Go and all third-party libraries updated to patch known vulnerabilities.
- **Principle of Least Privilege**: Tokens should be requested with the minimum necessary scopes.

---

## 🧪 Testing

Autentico includes a suite of unit and integration tests to ensure code quality and correctness. The `testify` library is used for assertions and mocking.

**Run the test suite:**

```bash
make test
# Or directly using Go:
# go test ./...
```

Tests cover critical functionalities such as:

- Token generation, validation, and revocation.
- User authentication and creation.
- OIDC endpoint behavior (e.g., `/authorize`, `/token`, `/userinfo`).
- Session management.
- Database interactions.

The `tests/` directory contains end-to-end style tests, while package-specific tests reside alongside the source code (e.g., `pkg/token/create_test.go`).

---

## 🤝 Contributing

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

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file in the repository for the full license text.
