test

# Autentico — OAuth 2.0 / OIDC Identity Provider

[![Go Report Card](https://goreportcard.com/badge/github.com/eugenioenko/autentico)](https://goreportcard.com/report/github.com/eugenioenko/autentico)
[![Test Coverage](https://img.shields.io/badge/coverage-73.4%25-green.svg)](https://github.com/eugenioenko/autentico)
[![Tests](https://img.shields.io/badge/tests-821-blue.svg)](https://github.com/eugenioenko/autentico)
[![OIDC Certified](https://img.shields.io/badge/OIDC-certified-brightgreen.svg)](https://openid.net/certification/)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-AGPL--v3-blue.svg)](LICENSE)

**Auténtico is a self-contained OAuth 2.0 / OpenID Connect (OIDC) Identity Provider built with Go. It handles the full authentication lifecycle — login, MFA, passkeys, sessions, token issuance, and admin — in a single binary backed by SQLite. No external database, no infrastructure dependencies, no ceremony.**

Identity infrastructure is typically complex to operate: a separate database to provision and back up, a cache tier, a worker queue, multiple services to keep running, and credentials to rotate. Auténtico takes a different approach. The entire IdP — authentication, token issuance, session management, and the admin UI — runs as one Go binary backed by a single SQLite file. You deploy one thing and it works.

Auténtico implements OAuth2 and OpenID Connect correctly. It is not a simplified or non-standard subset. Authorization Code + PKCE, refresh tokens, token introspection, OIDC discovery, RS256-signed JWTs, WebAuthn/passkeys, TOTP, and email OTP are all standard-compliant. The simplicity is operational, not protocol-level.

**Correctness is verified through 800+ tests, RFC-by-RFC compliance audits, official OIDC conformance tests, and full-flow load testing.**

---

## Documentation

Access the full documentation at [autentico.top](https://autentico.top)

## Live Demo

Try Autentico instantly: [Launch a Live Demo](https://demo.autentico.top/launch)

_Each demo session provisions a dedicated, ephemeral Autentico instance—isolated for your use, with all data and configuration automatically purged after 24 hours. No shared state, no persistence, no surprises._

## Using Autentico?

We'd love to hear from you — what you're protecting, what's working, what's missing.
[Share your use case in Discussions](https://github.com/eugenioenko/autentico/discussions/113)

---

## Why Auténtico?

Most production identity systems require you to operate multiple services before users can log in. A typical self-hosted setup involves a database server, a cache, a queue, and the identity service itself — each with its own configuration, backup requirements, and failure modes.

Auténtico removes that stack:

- **Single binary** — one executable, no sidecars, no process manager complexity
- **Embedded SQLite** — no separate database server; the entire state lives in one file
- **No external infrastructure** — no Redis, no Postgres, no message queues
- **Built-in admin UI** — a React dashboard compiled into the binary; nothing to deploy separately
- **Standards-compliant OAuth 2.0 / OIDC** — relying parties configure themselves automatically via OIDC Discovery; tokens are RS256-signed JWTs verifiable without calling home

The operational surface area is a binary and a `.env` file. That is a meaningful reduction in the things that can break.

The tradeoff is scale ceiling: SQLite serializes writes, and a single binary can't span multiple hosts. For most teams running internal tools, small-to-mid-sized applications, or self-hosted services, these constraints never become relevant. When they do, they're the right kind of problem to have.

---

## Who Auténtico Is For

Auténtico is a good fit for:

- **Small teams and startups** that need OAuth2/OIDC for their product but don't want to operate a full identity platform
- **Internal tools and self-hosted applications** where simplicity and low maintenance overhead matter more than enterprise-scale features
- **Developers evaluating OIDC** who want a running, real implementation to work against rather than a mock
- **Side projects and indie developers** who need user authentication without depending on a third-party service or running a heavy stack

It is not designed for organizations that require horizontal scaling of the auth tier, active-active multi-region deployments, or enterprise compliance features (SCIM, LDAP federation, custom authorization policies). Those requirements point to a different class of identity platform.

---

## Table of Contents

- [Why Auténtico?](#why-auténtico)
- [Who Auténtico Is For](#who-auténtico-is-for)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture Overview](#architecture-overview)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
  - [Bootstrap Settings (.env)](#bootstrap-settings-env)
  - [Global Settings (Runtime)](#global-settings-runtime)
  - [Per-Client Overrides](#per-client-overrides)
- [Authentication Modes](#authentication-modes)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Trusted Devices](#trusted-devices)
- [Admin UI](#admin-ui)
- [Account UI](#account-ui)
- [Endpoints](#endpoints)
- [Supported Grant Types](#supported-grant-types)
- [Client Interaction Examples](#client-interaction-examples)
- [Security Considerations](#security-considerations)
- [Deployment & Operations](#deployment--operations)
- [Testing](#testing)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Standards & Protocol

- **OIDC Discovery** — publishes `/.well-known/openid-configuration` so relying parties auto-configure without hardcoding endpoints
- **JWK Set** — exposes public signing keys at `/oauth2/.well-known/jwks.json` for independent token verification
- **RS256 JWT Signing** — asymmetric signing; the private key never leaves the IdP
- **Authorization Code Flow + PKCE** (RFC 7636, S256 enforced by default) — the right default for web and native apps
- **Resource Owner Password Credentials** — supported for legacy client compatibility (see [ROPC note](#on-ropc-support))
- **Refresh Token Grant** — long-lived sessions without re-authentication
- **Token Introspection** (RFC 7662) — for resource servers to validate opaque tokens
- **Token Revocation** (RFC 7009) — explicit token invalidation
- **UserInfo Endpoint** — standard OIDC identity claims
- **Keycloak-compatible paths** — `/oauth2/protocol/openid-connect/token` and `/oauth2/protocol/openid-connect/userinfo` are registered alongside standard paths, easing migration from Keycloak

### Authentication

- **Three auth modes** — `password`, `password_and_passkey`, or `passkey_only` — switchable at runtime without restart
- **Passkeys (WebAuthn)** — hardware-backed FIDO2 authentication via platform authenticators and security keys; passkey-only mode supports first-login registration in one flow
- **TOTP MFA** — time-based one-time passwords with in-browser QR code enrollment (no out-of-band enrollment link required)
- **Email OTP MFA** — one-time codes delivered via SMTP
- **Trusted Devices** — after MFA, users can mark a device as trusted for a configurable period, skipping MFA on return visits
- **Account Lockout** — configurable failed-attempt threshold and lockout duration, with admin unlock capability
- **SSO Sessions (IdP Sessions)** — persistent sessions across browser restarts with configurable idle timeout; returning users skip the login page entirely

### User & Client Management

- **Dynamic client registration** — register and manage OAuth2 clients (confidential and public) via REST API or Admin UI
- **Per-client configuration overrides** — token TTLs, allowed audiences, self-signup, session idle timeout, and trusted device settings can be tuned per client without touching global defaults
- **Self-signup** — optionally allow end users to register accounts on the login page, globally or per client
- **User CRUD** — full user lifecycle management with role support (`user`, `admin`)
- **Soft deletes** — users and clients are deactivated, not destroyed, preserving audit history
- **Account self-service** — users can manage their own profile, security settings, sessions, passkeys, MFA, and connected providers via the built-in Account UI

### Operations

- **Built-in Admin UI** — a React/Ant Design dashboard embedded into the binary at build time; zero separate deployments
- **Runtime settings** — most configuration lives in the database and can be updated via the Admin UI without restarting the server
- **Background cleanup** — a configurable background goroutine purges expired tokens, sessions, auth codes, MFA challenges, and passkey challenges; the retention window is tunable
- **Graceful shutdown** — SIGTERM handling drains in-flight requests before exit
- **Guided onboarding** — first-run setup flow that bootstraps the admin account; the server surfaces the onboarding URL at startup until complete
- **Docker-ready** — multi-stage Dockerfile produces a minimal Alpine image with nginx for TLS termination

---

## Tech Stack

| Layer       | Choice                        | Rationale                                                     |
| ----------- | ----------------------------- | ------------------------------------------------------------- |
| Language    | Go 1.23                       | Single-binary deployment, strong concurrency, type safety     |
| Database    | SQLite (`modernc.org/sqlite`) | No CGo, no external server, sufficient for IdP write patterns |
| JWT Signing | RS256 (RSA 2048)              | Asymmetric — relying parties verify without holding secrets   |
| WebAuthn    | `go-webauthn/webauthn`        | Standards-compliant FIDO2/WebAuthn implementation             |
| TOTP        | RFC 6238 compliant            | Compatible with Google Authenticator, Authy, 1Password, etc.  |
| CSRF        | `gorilla/csrf`                | Protects browser-facing form endpoints                        |
| Admin UI    | React + Ant Design (Vite)     | Embedded into the binary via `go:embed`                       |
| Testing     | Testify + in-memory SQLite    | Isolated, fast unit and integration tests                     |
| Docs        | Swagger/OpenAPI               | Interactive API reference                                     |

---

## Architecture Overview

### Package Structure

Each package in `pkg/` owns a vertical slice of IdP functionality. The convention is consistent: `model.go` for types, `handler.go` for HTTP, `create/read/update/delete.go` for database operations, `service.go` for business logic.

| Package             | Role                                                                             |
| ------------------- | -------------------------------------------------------------------------------- |
| `pkg/authorize`     | Authorization endpoint — renders login page, validates client and redirect URI   |
| `pkg/login`         | Login form submission, credential validation, MFA challenge creation             |
| `pkg/mfa`           | MFA challenge verification, TOTP enrollment, email OTP delivery                  |
| `pkg/passkey`       | WebAuthn registration and authentication ceremony handlers                       |
| `pkg/trusteddevice` | Trusted device token issuance and cookie management                              |
| `pkg/token`         | Token endpoint — authorization code exchange, refresh, revocation                |
| `pkg/session`       | OAuth2 session lifecycle and admin session management                            |
| `pkg/idpsession`    | IdP-level SSO sessions — cross-request browser sessions                          |
| `pkg/client`        | OAuth2 client registration, CRUD, and authentication                             |
| `pkg/user`          | User identity management — CRUD, authentication, lockout                         |
| `pkg/signup`        | Self-service user registration flow                                              |
| `pkg/onboarding`    | First-run admin account creation                                                 |
| `pkg/appsettings`   | Runtime settings — DB persistence, loading into config                           |
| `pkg/introspect`    | Token introspection endpoint                                                     |
| `pkg/userinfo`      | UserInfo endpoint                                                                |
| `pkg/wellknown`     | OIDC discovery document and JWKS                                                 |
| `pkg/middleware`    | CORS, CSRF, logging, admin auth, audience validation                             |
| `pkg/cleanup`       | Background goroutine for expired record purging                                  |
| `pkg/account`       | Account self-service API and embedded React Account UI (from `pkg/account/dist`) |
| `pkg/admin`         | Embedded Admin UI (static files + stats handler)                                 |
| `pkg/config`        | Bootstrap and runtime configuration                                              |
| `pkg/db`            | SQLite initialization, schema, and incremental migrations                        |
| `pkg/key`           | RSA key loading (env or ephemeral) and JWK Set generation                        |

### Architecture Philosophy

Auténtico treats operational simplicity as a first-class design goal. Each architectural decision is evaluated against the question: does this reduce or increase the operational burden on the person running this?

Eliminating the external database eliminates an entire category of failure modes. There is no connection pool to tune, no managed service to provision, no separate credential rotation for the database layer, and no network partition between the IdP and its storage. The result is an IdP you can run anywhere a Go binary runs — a VM, a container, a Raspberry Pi, a developer laptop.

The codebase is deliberately un-clever. Each package does one thing. There are no frameworks beyond the standard library, no abstraction layers that obscure what a request actually does. New contributors and future maintainers should be able to read any handler and understand the complete request lifecycle without jumping through multiple layers of indirection.

### Why SQLite

SQLite is an intentional architectural choice. For identity workloads at this scale, the write serialization limit (~500 sustained writes/sec) represents approximately 50,000 logins/hour — more than most deployments will ever approach. In exchange, you get zero operational overhead: no connection pool, no network partition, no separate credential management.

When load characteristics genuinely justify migration, the `pkg/db` boundary makes that tractable. Until then, the operational simplicity is worth considerably more than theoretical headroom.

**Observed performance** — full PKCE auth code flow (authorize → login → token → introspect → refresh), measured with k6 on a developer laptop, single process, SQLite backend:

| Concurrency | Error rate | Login p95 | Token p95 | Assessment |
|-------------|------------|-----------|-----------|------------|
| 20 VUs | 0% | 86ms | 54ms | Comfortable — imperceptible to users |
| 100 VUs | 0% | 611ms | 647ms | Supported — fully functional |
| 500 VUs | 0% | 3.36s | 3.89s | Degraded — users feel the wait |

In practice, "100 concurrent logins" corresponds to **10,000–20,000 daily active users** under a typical enterprise login distribution (morning peak, sessions lasting hours). The failure mode at high concurrency is graceful queuing — no errors, just latency — because SQLite's busy timeout absorbs write contention rather than returning errors.

Other operations (token refresh, introspection, OIDC discovery) are not bottlenecked by bcrypt and remain sub-10ms well beyond these concurrency levels.

See [`stress/README.md`](stress/README.md) for the full methodology and how to reproduce these numbers.

### Why RS256 over HS256

Symmetric signing (HS256) requires every party that verifies a token to also hold the signing secret. As relying parties multiply, so does the secret distribution problem. RS256 keeps the private key exclusively with Auténtico; relying parties verify independently using the public JWKS. This is the correct architecture for an IdP regardless of scale.

### On ROPC Support

The Resource Owner Password Credentials grant is deprecated in OAuth 2.1. It is supported here deliberately to maintain backward compatibility with legacy clients and tooling that teams may already depend on. If you are building something new, use the Authorization Code flow. ROPC support can be restricted to specific clients by not granting them the `password` grant type during registration.

---

## Getting Started

The full setup requires three commands: initialize configuration, start the server, and complete onboarding in the browser. No database to provision, no external services to configure.

### Prerequisites

- Go 1.21 or later
- `make` (optional, for Makefile targets)
- Node.js 20+ and `pnpm` (only if building the Admin UI from source)

### Quick Start (pre-built binary)

Download the latest binary from [GitHub Releases](https://github.com/eugenioenko/autentico/releases), then:

```bash
# Generate .env with RSA key, CSRF secret, and token secrets
./autentico init

# Create the first admin account (or use the browser at /onboard after starting)
./autentico onboard --username admin --password yourpassword --email admin@example.com --auto-migrate

# Start the server
./autentico start
```

The `onboard` command creates the admin account headlessly — useful for CI/CD, Docker, and automated deployments. Credentials can also be passed via environment variables (`AUTENTICO_ADMIN_USERNAME`, `AUTENTICO_ADMIN_PASSWORD`, `AUTENTICO_ADMIN_EMAIL`). Alternatively, start the server first and visit `http://localhost:9999/onboard/` to complete setup in the browser.

### Building from Source

**1. Clone the repository**

```bash
git clone https://github.com/eugenioenko/autentico.git
cd autentico
```

**2. Build**

```bash
# Build Admin UI + Go binary (requires pnpm)
make build

# Build Go binary only (uses the pre-built Admin UI in pkg/admin/dist)
make build-go
```

**3. Initialize configuration**

```bash
./autentico init
# Or with a custom URL:
./autentico init --url https://auth.example.com
```

This generates a `.env` file with a fresh RSA private key, CSRF secret, and token signing secrets. The key is embedded as a base64-encoded PEM — no separate key file to manage.

**4. Start the server**

```bash
./autentico start
```

The server starts on port 9999 and prints the key URLs (server, admin, well-known, authorize, token) to stdout.

**5. Complete onboarding**

If this is a fresh database, the startup output shows an **ONBOARDING** URL (e.g., `http://localhost:9999/onboard/`). Open it and fill in your administrator credentials. The URL is shown on every startup until onboarding is complete.

---

## Configuration

Auténtico uses a three-layer configuration system, ordered from most to least immutable:

```
.env (bootstrap)  →  settings table (runtime)  →  clients table (per-client)
     immutable            hot-reloadable               per-audience
```

### Bootstrap Settings (.env)

These are infrastructure-level settings read once at startup. Changing them requires a server restart. Generated by `autentico init`.

| Variable                         | Description                                                    | Default                 |
| -------------------------------- | -------------------------------------------------------------- | ----------------------- |
| `AUTENTICO_APP_URL`              | Base URL (used to derive issuer, domain, port)                 | `http://localhost:9999` |
| `AUTENTICO_APP_OAUTH_PATH`       | Path prefix for OAuth2 endpoints                               | `/oauth2`               |
| `AUTENTICO_APP_ENABLE_CORS`      | Enable CORS middleware                                         | `true`                  |
| `AUTENTICO_DB_FILE_PATH`         | SQLite database file path                                      | `./db/autentico.db`     |
| `AUTENTICO_PRIVATE_KEY`          | Base64-encoded RSA private key PEM                             | _(generated by init)_   |
| `AUTENTICO_ACCESS_TOKEN_SECRET`  | HMAC secret for access token signing                           | _(generated by init)_   |
| `AUTENTICO_REFRESH_TOKEN_SECRET` | HMAC secret for refresh token signing                          | _(generated by init)_   |
| `AUTENTICO_CSRF_SECRET_KEY`      | Secret for CSRF token generation                               | _(generated by init)_   |
| `AUTENTICO_CSRF_SECURE_COOKIE`   | Require Secure flag on CSRF cookie                             | `true`                  |
| `AUTENTICO_REFRESH_TOKEN_COOKIE_ONLY` | **Opt-in security enhancement.** Delivers the refresh token as an `HttpOnly` cookie instead of in the JSON response body, preventing JavaScript (including XSS) from reading it. Non-standard — only enable if your client reads the refresh token from a cookie. | `false` |
| `AUTENTICO_IDP_SESSION_SECURE`   | Require Secure flag on IdP session cookie                      | `true`                  |
| `AUTENTICO_JWK_CERT_KEY_ID`      | Key ID (`kid`) in the JWK Set                                  | `autentico-key-1`       |
| `AUTENTICO_RATE_LIMIT_RPS`       | Sustained requests/sec per IP on auth endpoints (0 = disabled) | `5`                     |
| `AUTENTICO_RATE_LIMIT_BURST`     | Burst size for the per-second limiter                          | `10`                    |
| `AUTENTICO_RATE_LIMIT_RPM`       | Sustained requests/min per IP (long-term cap)                  | `20`                    |
| `AUTENTICO_RATE_LIMIT_RPM_BURST` | Burst size for the per-minute limiter                          | `20`                    |

> In production, set all `*_SECURE` flags to `true` once you have TLS.

### Global Settings (Runtime)

These live in the `settings` database table and are loaded into memory at startup. They can be updated via the Admin UI or `PUT /admin/api/settings` without restarting the server — changes take effect on the next request.

| Setting Key                      | Description                                            | Default          |
| -------------------------------- | ------------------------------------------------------ | ---------------- |
| `access_token_expiration`        | Access token lifetime                                  | `15m`            |
| `refresh_token_expiration`       | Refresh token lifetime                                 | `720h` (30 days) |
| `authorization_code_expiration`  | Auth code lifetime                                     | `10m`            |
| `access_token_audience`          | JWT `aud` claim (JSON array)                           | `[]`             |
| `auth_mode`                      | `password` \| `password_and_passkey` \| `passkey_only` | `password`       |
| `mfa_enabled`                    | Require MFA for all users                              | `false`          |
| `mfa_method`                     | `totp` \| `email`                                      | `totp`           |
| `trust_device_enabled`           | Allow users to bypass MFA on trusted devices           | `false`          |
| `trust_device_expiration`        | Trusted device token lifetime                          | `720h` (30 days) |
| `sso_session_idle_timeout`       | IdP session idle timeout (`0` = disabled)              | `0`              |
| `allow_self_signup`              | Allow end users to register their own accounts         | `false`          |
| `account_lockout_max_attempts`   | Failed logins before account lock                      | `5`              |
| `account_lockout_duration`       | How long the account stays locked                      | `15m`            |
| `passkey_rp_name`                | WebAuthn relying party name shown to users             | `Autentico`      |
| `cleanup_interval`               | How often expired records are purged                   | `6h`             |
| `cleanup_retention`              | Minimum age for a record to be eligible for cleanup    | `24h`            |
| `validation_min_username_length` | Minimum username length                                | `4`              |
| `validation_max_username_length` | Maximum username length                                | `64`             |
| `validation_min_password_length` | Minimum password length                                | `6`              |
| `validation_max_password_length` | Maximum password length                                | `64`             |
| `validation_username_is_email`   | Require username to be a valid email format            | `false`          |
| `validation_email_required`      | Require email field at registration                    | `false`          |
| `smtp_host`                      | SMTP server hostname                                   | _(empty)_        |
| `smtp_port`                      | SMTP server port                                       | `587`            |
| `smtp_username`                  | SMTP authentication username                           | _(empty)_        |
| `smtp_password`                  | SMTP authentication password                           | _(empty)_        |
| `smtp_from`                      | From address for outbound email                        | _(empty)_        |
| `theme_title`                    | Page title shown on login/MFA pages                    | `Autentico`      |
| `theme_logo_url`                 | URL to a logo image displayed on login page            | _(empty)_        |
| `theme_css_inline`               | Inline CSS injected into login page `<style>`          | _(empty)_        |
| `theme_css_file`                 | Path to a CSS file loaded at runtime                   | _(empty)_        |

### Per-Client Overrides

Each registered client can override a subset of global settings. Unset fields fall through to the global value — there is no need to repeat the default. Overrides are managed via the client registration API or Admin UI.

| Field                           | Description                                                     |
| ------------------------------- | --------------------------------------------------------------- |
| `access_token_expiration`       | Token lifetime for this client's tokens                         |
| `refresh_token_expiration`      | Refresh token lifetime for this client                          |
| `authorization_code_expiration` | Auth code TTL                                                   |
| `allowed_audiences`             | Additional `aud` values in tokens for this client               |
| `allow_self_signup`             | Override self-signup for this client's login page               |
| `sso_session_idle_timeout`      | Override idle timeout for sessions originating from this client |
| `trust_device_enabled`          | Enable or disable trusted devices for this client               |
| `trust_device_expiration`       | Trust duration for this client's users                          |

---

## Authentication Modes

Auténtico's `auth_mode` setting controls which credential types are accepted. It can be changed at runtime.

| Mode                   | Behavior                                                                                                                                                                      |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `password`             | Standard username + password. MFA is applied on top if `mfa_enabled` is true.                                                                                                 |
| `password_and_passkey` | Users can authenticate with either password or a registered passkey. Password flow optionally includes MFA.                                                                   |
| `passkey_only`         | Password authentication is disabled. Users authenticate exclusively with passkeys. First-time users are guided through passkey registration during their first login attempt. |

---

## Multi-Factor Authentication

When `mfa_enabled` is `true`, all users must complete an MFA step after password authentication.

**TOTP**

- Users who have not yet enrolled are shown a QR code on their next login
- The QR code can be scanned with any TOTP app (Google Authenticator, Authy, 1Password, Bitwarden, etc.)
- Once enrolled, TOTP is required on every subsequent login (unless on a trusted device)
- The secret is stored per-user in the database; enrollment happens in-browser without any email or out-of-band step

**Email OTP**

- A one-time code is generated and emailed to the user on each login
- Requires SMTP settings (`smtp_host`, `smtp_port`, `smtp_username`, `smtp_password`, `smtp_from`) to be configured
- No enrollment step — the code is sent immediately

---

## Trusted Devices

When `trust_device_enabled` is `true`, the MFA page shows a "Trust this device" checkbox. If checked, a cryptographic token is stored in a long-lived cookie on the user's browser. On subsequent logins from the same device, MFA is skipped for the duration of `trust_device_expiration`.

Trusted device tokens are stored in the `trusted_devices` table and cleaned up automatically by the background cleanup process.

---

## Admin UI

The Admin UI is a React application (built with Ant Design) embedded into the Go binary via `go:embed`. It is served at `/admin/` and authenticates through Auténtico itself using the auto-seeded `autentico-admin` OIDC client.

### Pages

**Dashboard**

- Live stats: total users, active clients, active sessions, recent logins (last 24h)
- Quick action buttons: Create User, Create Client

**Users**

- Full user list with username, email, role, status (active, locked, failed attempts), and creation date
- Create users with role selection
- Edit user details and role
- Deactivate users (soft delete)
- Unlock accounts that have been locked by the account lockout policy

**Clients**

- Full client list with name, client ID, type (confidential/public), grant types, and status
- Create clients with all registration options (redirect URIs, grant types, response types, scopes, auth method, client type)
- Edit client configuration
- View client details (including redirect URIs, grant types, and creation metadata)
- Deactivate clients

**Sessions**

- Session list with ID, user, IP address, user agent, creation time, expiry, and status (active/expired/deactivated)
- Filter by user ID or status
- Deactivate individual sessions (forces logout)
- View full session details

### Settings API

The Admin UI communicates with the server over a dedicated admin API. Settings can also be managed directly via HTTP:

```bash
# Read all current settings (sensitive keys omitted)
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9999/admin/api/settings

# Update settings (hot-reloaded immediately, no restart needed)
curl -X PUT \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mfa_enabled": "true", "mfa_method": "totp"}' \
  http://localhost:9999/admin/api/settings
```

### Building the Admin UI

The pre-built Admin UI is committed to the repository in `pkg/admin/dist/` and is embedded at compile time. If you modify the frontend source:

```bash
# Build the Admin UI and copy it into the embed directory
make admin-ui-build

# Or build everything (Admin UI + Go binary) in one step
make build
```

### Admin UI Development Mode

```bash
# Terminal 1: start the Go server
make run

# Terminal 2: start the Vite dev server (hot-reload)
cd admin-ui && pnpm dev
```

The dev server runs at `http://localhost:5173/admin/` and proxies API requests to the Go server on port 9999.

---

## Account UI

The Account UI is a React SPA (built with React 19, React Router v7, TanStack Query, and Tailwind CSS) embedded into the Go binary via `go:embed`. It is served at `/account/` and lets authenticated users manage their own profile and security settings without involving an administrator.

Authentication is handled automatically: on first visit, users are redirected through the standard OIDC Authorization Code flow using the auto-seeded `autentico-account` public client, then returned to `/account/callback` to complete token exchange.

### Pages

**Dashboard**

- Security status summary — shows whether TOTP is configured and displays the user's username and email
- Quick link to the Security page for configuration

**Profile**

- Edit personal information; visible fields are controlled by backend settings:
  - Username (if `allow_username_change` is enabled)
  - Email (if `allow_email_change` is enabled)
  - First name, last name, phone number, profile picture URL, locale
  - Street address, city, state/region, postal code, country

**Security**

- **Password**: Change password with current password verification
- **TOTP (Two-Factor Authentication)**: Set up TOTP by scanning a QR code in any authenticator app (Google Authenticator, Authy, 1Password, etc.) and confirming with a 6-digit code; disable TOTP with password confirmation
- **Passkeys**: Register new passkeys via WebAuthn ceremony, view existing passkeys with creation date, rename or remove any passkey

**Sessions**

- List all active OAuth sessions with IP address, user agent, last activity timestamp, and creation time
- Current session is marked with a badge
- Revoke any other session individually (forces logout on that device)

**Trusted Devices**

- List devices that currently bypass MFA prompts, with device name, last used date, and expiration
- Revoke any trusted device to require MFA on its next login

**Connected Providers**

- List external identity providers (e.g., federated SSO) linked to the account, with provider name, associated email, and connection date
- Disconnect a provider; lockout prevention blocks disconnection if it is the user's only login method and they have no password

### Building the Account UI

The pre-built Account UI is committed to the repository in `pkg/account/dist/` and embedded at compile time. If you modify the frontend source:

```bash
# Build Account UI and copy assets into the embed directory
make account-ui-build

# Or build everything (Admin UI + Account UI + Go binary) in one step
make build
```

### Account UI Development Mode

```bash
# Terminal 1: start the Go server
make run

# Terminal 2: start the Vite dev server (hot-reload)
cd account-ui && pnpm dev
```

The dev server proxies API requests to the Go server on port 9999.

---

## Endpoints

### OIDC Discovery & Identity

| Endpoint                                   | Method   | Description                                   |
| ------------------------------------------ | -------- | --------------------------------------------- |
| `/.well-known/openid-configuration`        | GET      | OIDC discovery document                       |
| `/oauth2/.well-known/jwks.json`            | GET      | JWK Set — public keys for token verification  |
| `/oauth2/certs`                            | GET      | Alias for JWKS (legacy path)                  |
| `/oauth2/authorize`                        | GET      | Authorization endpoint — renders login page   |
| `/oauth2/token`                            | POST     | Token endpoint — code exchange, refresh, ROPC |
| `/oauth2/protocol/openid-connect/token`    | POST     | Keycloak-compatible token path                |
| `/oauth2/userinfo`                         | GET/POST | UserInfo endpoint                             |
| `/oauth2/protocol/openid-connect/userinfo` | GET/POST | Keycloak-compatible userinfo path             |
| `/oauth2/introspect`                       | POST     | Token introspection (RFC 7662)                |
| `/oauth2/revoke`                           | POST     | Token revocation (RFC 7009)                   |
| `/oauth2/logout`                           | POST     | Session logout                                |

### Authentication Flows

| Endpoint                          | Method   | Description                                         |
| --------------------------------- | -------- | --------------------------------------------------- |
| `/oauth2/login`                   | POST     | Username/password form submission                   |
| `/oauth2/mfa`                     | GET/POST | MFA challenge render and verification               |
| `/oauth2/signup`                  | GET/POST | Self-service user registration (when enabled)       |
| `/onboard`                        | GET/POST | First-run admin onboarding (disabled after first user) |
| `/oauth2/passkey/login/begin`     | GET      | Begin WebAuthn authentication/registration ceremony |
| `/oauth2/passkey/login/finish`    | POST     | Complete WebAuthn authentication ceremony           |
| `/oauth2/passkey/register/finish` | POST     | Complete WebAuthn registration ceremony             |

### Client Registration (Admin Only)

| Endpoint                       | Method | Description                     |
| ------------------------------ | ------ | ------------------------------- |
| `/oauth2/register`             | POST   | Register a new OAuth2 client    |
| `/oauth2/register`             | GET    | List all registered clients     |
| `/oauth2/register/{client_id}` | GET    | Get a specific client           |
| `/oauth2/register/{client_id}` | PUT    | Update a client's configuration |
| `/oauth2/register/{client_id}` | DELETE | Deactivate a client             |

### Admin API (Admin Auth Required)

| Endpoint                  | Method              | Description                  |
| ------------------------- | ------------------- | ---------------------------- |
| `/admin/api/users`        | GET/POST            | List or create users         |
| `/admin/api/users`        | PUT/DELETE          | Update or deactivate users   |
| `/admin/api/users/unlock` | POST                | Unlock a locked user account |
| `/admin/api/clients`      | GET/POST/PUT/DELETE | Client management            |
| `/admin/api/sessions`     | GET/DELETE          | Session management           |
| `/admin/api/stats`        | GET                 | Dashboard statistics         |
| `/admin/api/settings`     | GET/PUT             | Read/update runtime settings |

### User Self-Service

| Endpoint | Method | Description                                 |
| -------- | ------ | ------------------------------------------- |
| `/user`  | POST   | Create a user (for API-driven provisioning) |

### Account Self-Service API (Bearer Token Required)

| Endpoint                                | Method       | Description                                    |
| --------------------------------------- | ------------ | ---------------------------------------------- |
| `/account/api/settings`                 | GET          | UI configuration (auth mode, field visibility) |
| `/account/api/profile`                  | GET / PUT    | Get or update user profile                     |
| `/account/api/password`                 | POST         | Change password                                |
| `/account/api/sessions`                 | GET          | List active OAuth sessions                     |
| `/account/api/sessions/{id}`            | DELETE       | Revoke a session                               |
| `/account/api/passkeys`                 | GET          | List registered passkeys                       |
| `/account/api/passkeys/register/begin`  | POST         | Begin WebAuthn registration ceremony           |
| `/account/api/passkeys/register/finish` | POST         | Complete WebAuthn registration ceremony        |
| `/account/api/passkeys/{id}`            | PATCH/DELETE | Rename or remove a passkey                     |
| `/account/api/mfa`                      | GET          | Get MFA status                                 |
| `/account/api/mfa/totp/setup`           | POST         | Initialize TOTP enrollment (returns QR code)   |
| `/account/api/mfa/totp/verify`          | POST         | Confirm TOTP enrollment with a 6-digit code    |
| `/account/api/mfa/totp`                 | DELETE       | Disable TOTP                                   |
| `/account/api/trusted-devices`          | GET          | List trusted devices                           |
| `/account/api/trusted-devices/{id}`     | DELETE       | Revoke a trusted device                        |
| `/account/api/connected-providers`      | GET          | List connected external providers              |
| `/account/api/connected-providers/{id}` | DELETE       | Disconnect an external provider                |

---

## Supported Grant Types

| Grant Type                    | Use Case                                                        |
| ----------------------------- | --------------------------------------------------------------- |
| `authorization_code` (+ PKCE) | Web apps, SPAs, native apps. The recommended default.           |
| `refresh_token`               | Obtaining new access tokens without re-authenticating the user. |
| `password` (ROPC)             | Legacy clients and trusted internal tooling. Use with caution.  |

---

## Client Interaction Examples

### Register an OAuth2 Client (Admin Only)

```bash
# Obtain an admin access token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:9999/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin@example.com&password=AdminPassword123!" \
  | jq -r '.access_token')

# Register a confidential client
curl -X POST http://localhost:9999/oauth2/register \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["https://myapp.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "client_type": "confidential",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

The `client_secret` in the response is shown once. Store it securely — it is bcrypt-hashed in the database and cannot be retrieved.

### Register a Public Client (SPA/Mobile)

```bash
curl -X POST http://localhost:9999/oauth2/register \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My SPA",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code"],
    "client_type": "public",
    "token_endpoint_auth_method": "none"
  }'
```

### Authorization Code Flow (with PKCE)

```javascript
// Generate PKCE parameters
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

const codeVerifier = generateCodeVerifier();
sessionStorage.setItem("code_verifier", codeVerifier);

const params = new URLSearchParams({
  response_type: "code",
  client_id: "your_client_id",
  redirect_uri: "https://myapp.com/callback",
  scope: "openid profile email",
  state: crypto.randomUUID(),
  nonce: crypto.randomUUID(),
  code_challenge: await generateCodeChallenge(codeVerifier),
  code_challenge_method: "S256",
});

window.location.href = `http://localhost:9999/oauth2/authorize?${params}`;
```

### Token Exchange

```bash
# Confidential client (client_secret_basic — recommended)
curl -X POST http://localhost:9999/oauth2/token \
  -u "your_client_id:your_client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=https://myapp.com/callback"

# Public client (PKCE)
curl -X POST http://localhost:9999/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=your_client_id&code=YOUR_CODE&redirect_uri=https://myapp.com/callback&code_verifier=YOUR_CODE_VERIFIER"
```

A successful response contains `access_token`, `id_token`, `refresh_token`, `token_type`, and `expires_in`.

---

## Security Considerations

As an identity provider, Auténtico is a critical trust boundary. The following considerations apply in production:

- **TLS** — always deploy behind a reverse proxy with TLS. Tokens must never travel over plaintext. Set all `*_SECURE` bootstrap flags to `true`.
- **Secrets** — the `.env` secrets (`AUTENTICO_PRIVATE_KEY`, `*_SECRET`, `*_KEY`) must be generated fresh per deployment and stored with appropriate access controls (environment injection, secrets manager).
- **CSRF** — `gorilla/csrf` protects all browser-facing form endpoints. The CSRF secret must be stable across restarts (so set `AUTENTICO_CSRF_SECRET_KEY` explicitly in production rather than regenerating it).
- **Redirect URI validation** — redirect URIs are strictly matched against registered client URIs. Wildcards are not supported.
- **Client secrets** — stored as bcrypt hashes. The plaintext is only available at registration time.
- **Password hashing** — user passwords are bcrypt-hashed.
- **Account lockout** — configure `account_lockout_max_attempts` and `account_lockout_duration` to limit single-account brute-force exposure.
- **Rate limiting** — built-in two-tier per-IP rate limiter on `/oauth2/login`, `/oauth2/mfa`, `/oauth2/token`, and `/oauth2/passkey/login/finish`. A per-second limit (default 5 rps / burst 10) stops rapid bursts; a per-minute limit (default 20 rpm / burst 20) caps sustained enumeration. Set `AUTENTICO_RATE_LIMIT_RPS=0` to disable both.
- **RS256 signing** — the RSA private key never leaves the server. Relying parties verify tokens using the public JWKS.
- **ROPC scope** — restrict the password grant to only clients that genuinely need it by omitting `"password"` from other clients' `grant_types`.

---

## Deployment & Operations

### Single Binary (Simplest)

```bash
./autentico init --url https://auth.example.com
./autentico onboard --username admin --password "$ADMIN_PASSWORD" --auto-migrate
./autentico start
```

Place an nginx or Caddy instance in front for TLS. The `onboard` step is optional if you prefer to use the browser wizard at `/onboard` after starting.

### Docker

The included `dockerfile` produces a minimal Alpine image with nginx for TLS termination. It uses a self-signed certificate by default — replace with a real certificate in production.

```bash
docker build -t autentico .
docker run -p 443:443 -p 9999:9999 \
  -e AUTENTICO_APP_URL=https://auth.example.com \
  -e AUTENTICO_PRIVATE_KEY="..." \
  -e AUTENTICO_ACCESS_TOKEN_SECRET="..." \
  -e AUTENTICO_REFRESH_TOKEN_SECRET="..." \
  -e AUTENTICO_CSRF_SECRET_KEY="..." \
  -v /data:/app/db \
  autentico
```

### Docker Compose

```bash
docker compose up -d
```

The provided `docker-compose.yml` maps ports 9999 and 443.

### Reverse Proxy (nginx example)

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

### Backup

```bash
# Hot backup (safe while the server is running)
sqlite3 /data/autentico.db ".backup /backup/autentico-$(date +%Y%m%d-%H%M%S).db"
```

The database is a single file. Back it up like any other file. SQLite's WAL mode (the default) allows consistent hot backups.

### Database Migrations

Autentico uses explicit, versioned schema migrations. The binary will refuse to start if the database schema is behind:

```
database is at version 1, this binary requires version 2 — run: autentico migrate
```

To apply pending migrations:

```bash
autentico migrate
```

The command shows the current and target versions, warns that migrations are irreversible, and asks you to type the target version number to confirm. Back up your database file before proceeding.

For automated environments (Docker, CI), use the `--auto-migrate` flag to apply migrations automatically on startup:

```bash
autentico start --auto-migrate
```

### Health Check

`GET /.well-known/openid-configuration` serves as a reliable liveness and readiness probe — it requires the database and key to be functional.

### Go Runtime Tuning

```bash
# In containerized environments, set GOMAXPROCS explicitly
# Go may not correctly detect container CPU quotas
GOMAXPROCS=4 ./autentico start

# Reduce GC pressure at the cost of higher memory usage
GOGC=200 ./autentico start
```

SQLite write serialization is the primary throughput bottleneck, not CPU parallelism. GOMAXPROCS primarily benefits concurrent request handling and cryptographic operations.

### Migration Path

When SQLite write throughput becomes a constraint (typically > 100k daily active users with high concurrent write peaks), the `pkg/db` abstraction allows a backend swap. A typical migration path is dual-write (SQLite as source of truth → PostgreSQL as replica) followed by a read cutover and finalization.

---

## Testing

Auténtico treats authentication as a correctness-critical system, not just an application layer. Testing is validated at four levels: automated tests, RFC compliance review, OIDC conformance testing, and load testing.

### Testing Philosophy

Testing is designed around three principles:

- **Spec alignment over implementation convenience** — behavior is derived from RFC and OIDC specifications, not inferred
- **Full-flow validation** — tests exercise complete authentication lifecycles, not isolated functions
- **Failure-driven coverage** — edge cases and negative paths are explicitly tested (invalid tokens, expired codes, replay attempts, malformed requests)

The goal is not just high coverage, but **high confidence that every externally observable behavior matches the protocol specification**.

### Automated Tests

**821+ test functions** across unit, integration, and end-to-end tests at **73.4% coverage**.

- **Unit tests** (500+) — validate deterministic logic (token generation, validation rules, claim construction)
- **Integration tests** (150+) — verify cross-package invariants (authorization code lifecycle, session ↔ token relationships, client authentication rules)
- **End-to-end tests** (75+) — execute full OAuth2/OIDC flows over HTTP against a real server instance, including redirects, cookies, and token exchange

Critical invariants (e.g., "authorization code can only be used once", "refresh token rotation invalidates previous token") are tested explicitly across layers.

```bash
make test                                        # Run all tests
go test ./pkg/token/... -v                       # Run a specific package
go test -run TestCreateUser ./pkg/user/... -v    # Run a single test
go test ./tests/e2e/... -v                       # Run end-to-end tests only
```

Tests run with `-p 1` (sequential) because they share a process-level SQLite handle. Unit tests use an in-memory database, making them fast and isolated.

### RFC Compliance Review

Unlike typical implementations that rely on partial compliance or framework defaults, Auténtico performs a **systematic, spec-driven audit** of every protocol feature.

Each RFC is treated as a source of truth:
- Every **MUST** requirement is implemented and verified
- **SHOULD/MAY** clauses are evaluated and explicitly accepted or rejected
- All decisions are documented and tested

The review is structured as a 10-phase audit. Each phase reads the spec, verifies every MUST/SHOULD/MAY requirement against the implementation, annotates the code with inline RFC section references, adds both positive and negative tests, and checks the Security Considerations section.

| Phase | Spec | Status |
|---|---|---|
| 1 | RFC 6749 — OAuth 2.0 Core | ✅ Done |
| 2 | RFC 6750 — Bearer Token Usage | ✅ Done |
| 3 | RFC 7636 — PKCE | ✅ Done |
| 4 | RFC 7009 — Token Revocation | ✅ Done |
| 5 | RFC 7662 — Token Introspection | ✅ Done |
| 6 | OIDC Core 1.0 | ✅ Done |
| 7 | OIDC Discovery 1.0 | ✅ Done |
| 8 | OIDC RP-Initiated Logout 1.0 | ✅ Done |
| 9 | RFC 7591 — Dynamic Client Registration | ✅ Done |
| 10 | RFC 8414 — Authorization Server Metadata | ✅ Done |

This process effectively turns the RFCs into an executable specification enforced by tests.

The review found and fixed **11 protocol-level bugs**, including:

- Incorrect edge-case handling in token validation
- Missing negative-path checks (e.g., malformed or replayed inputs)
- Subtle spec violations that would not surface in normal testing

These were identified *by reading the RFCs line-by-line*, not by observing runtime failures — a class of issues that typical test suites miss. See [`rfc/rfc.md`](rfc/rfc.md) for the full bug inventory, MUST/SHOULD/MAY compliance tables, and per-phase test lists. All protocol-facing code now carries inline comments referencing the exact spec section that mandates the behavior.

### OIDC Conformance Testing

Auténtico passes the [OpenID Foundation `oidcc-basic-certification-test-plan`](https://openid.net/certification/) — the official conformance test suite for Basic OpenID Providers. The suite covers the full Authorization Code flow: discovery, authorization, token exchange, token refresh, ID token validation, UserInfo, and session management.

Passing this suite validates interoperability with real-world OIDC clients and confirms that Auténtico behaves as a standards-compliant OpenID Provider under strict test conditions. These are the same tests used in the official OIDC certification process.

```bash
# Start Auténtico with conformance-compatible settings (HTTP, no rate limiting)
make conformance-server

# Pull and start the conformance suite at https://localhost:8443
make conformance-suite
```

### Load Testing

Stress tests using [k6](https://k6.io) exercise the full PKCE auth code flow (authorize → login → token exchange → introspect → refresh). See [`stress/README.md`](stress/README.md) for the full methodology, test profiles, and how to reproduce.

| Concurrency | Error rate | Login p95 | Token p95 | Assessment |
|-------------|------------|-----------|-----------|------------|
| 20 VUs | 0% | 86ms | 54ms | Comfortable — imperceptible to users |
| 100 VUs | 0% | 611ms | 647ms | Supported — fully functional |
| 500 VUs | 0% | 3.36s | 3.89s | Degraded — users feel the wait |

*Measured on a developer laptop, single process, SQLite backend. The bottleneck is bcrypt, not SQLite — real-world traffic is much lighter than all-login load because SSO sessions and refresh tokens eliminate most password checks.*

### Reproducibility

All testing layers are reproducible locally:

- Automated tests: `make test`
- RFC audit artifacts: see [`rfc/rfc.md`](rfc/rfc.md)
- OIDC conformance suite: `make conformance-suite`
- Load testing: see [`stress/README.md`](stress/README.md)

No internal or proprietary tooling is required — the entire validation pipeline is transparent and executable by anyone.

---

## API Documentation

**Interactive Swagger UI:**

```bash
make docs
# Opens at http://localhost:8888/swagger/index.html
```

**Static HTML reference:**

The pre-generated HTML API reference is available at [`/docs/index.html`](docs/index.html) in the repository, and hosted at [GitHub Pages](https://eugenioenko.github.io/autentico/index.html).

---

## Contributing

Contributions are welcome. Before starting significant work, open an issue to align on approach.

1. Fork the repository and create a feature branch
2. Make your changes; follow existing Go conventions and package structure
3. Add or update tests — `make test` must pass
4. Submit a pull request with a clear description of the change and its motivation

---

## License

MIT. See [`LICENSE`](LICENSE) for the full text.

