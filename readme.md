# 🔐 Autentico OIDC

**Autentico** is an OpenID Connect (OIDC) compliant authentication server built with Go and SQLite. It supports modern authentication flows, session management, and JWT-based authorization out of the box.

---

## ✨ Features

- ✅ OIDC & OAuth2 compliant
- 🔑 Authorization Code Flow (with PKCE)
- 🔄 Refresh Token support
- 🔍 Token introspection & revocation
- 🔒 Secure session management
- 📦 Lightweight and embeddable
- 🛡️ CSRF protection using Gorilla CSRF
- 📜 Swagger API documentation

---

## 🚀 Quick Start

### Requirements

- Go 1.21+
- SQLite or PostgreSQL
- Docker (optional)

### Build and Run

```bash
# Clone the repository
git clone https://github.com/eugenioenko/autentico.git
cd autentico

# Build the application
make build

# Run the application
make run
```

---

## 📜 Swagger Documentation

### Running Swagger Server

To view the Swagger API documentation, you can run the Swagger server:

```bash
go run cmd/swagger.go
```

The Swagger UI will be available at: [http://localhost:8888/swagger/index.html](http://localhost:8888/swagger/index.html)

---

## ⚙️ Configuration

The configuration is managed via the `pkg/config/config.go` file. Below are the key settings:

- **App Settings**:

  - `AppDomain`: Default is `localhost`.
  - `AppPort`: Default is `8080`.
  - `AppURL`: Base URL for the application.

- **Authentication**:

  - `AuthAccessTokenExpiration`: Default is `15m`.
  - `AuthRefreshTokenExpiration`: Default is `30d`.
  - `AuthAllowedRedirectURIs`: List of allowed redirect URIs.

- **Security**:
  - `AuthCSRFProtectionSecretKey`: Secret key for CSRF protection.
  - `AuthCSRFSecureCookie`: Set to `true` in production.

---

## 🔐 Endpoints

### OpenID Connect Endpoints

- **Authorization**: `/oauth2/authorize`
- **Token**: `/oauth2/token`
- **User Info**: `/oauth2/userinfo`
- **Token Revocation**: `/oauth2/revoke`
- **Token Introspection**: `/oauth2/introspect`
- **Logout**: `/oauth2/logout`

### Well-Known Configuration

- **OIDC Discovery**: `/.well-known/openid-configuration`

### User Management

- **Create User**: `/users/create`

---

## 🧪 Supported Flows

- **Authorization Code Flow** (with PKCE)
- **Resource Owner Password Credentials Flow**

---

## 🧑‍💻 Client Registration

Client registration is currently manual. Update the `AuthAllowedRedirectURIs` in the configuration to include your client application's redirect URI.

---

### Register a User

```bash
curl -X POST http://localhost:8080/users/create \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password123", "email": "user@example.com"}'
```

### Authorization Request

```bash
curl -G http://localhost:8080/oauth2/authorize \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=your-client-id" \
  --data-urlencode "redirect_uri=https://your-client-app.com/callback" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=xyz123"
```

### Token Exchange

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=your-authorization-code" \
  -d "redirect_uri=https://your-client-app.com/callback" \
  -d "client_id=your-client-id"
```

---

## 🔧 Integration Guides

### Using with Postman

1. Import the OIDC discovery URL: `http://localhost:8080/.well-known/openid-configuration`.
2. Configure your client ID and redirect URI in Postman.
3. Test the Authorization Code Flow.

### Using with React

- Use libraries like `oidc-client` or `react-oauth2-code-pkce` to integrate with Autentico.

---

## 🛡️ Security Practices

- Use HTTPS in production.
- Restrict allowed redirect URIs.
- Enable CSRF protection (`AuthCSRFSecureCookie`).

---

## 🧪 Testing & Conformance

Run the test suite:

```bash
make test
```

The project uses `testify` for assertions and includes tests for:

- Token generation and revocation
- User authentication
- OIDC endpoints

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## 🏷️ Badges

![Go Version](https://img.shields.io/badge/Go-1.21-blue)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
