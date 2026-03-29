# Autentico

A self-contained OpenID Connect (OIDC) Identity Provider built with Go and SQLite.

Implements the full authentication lifecycle: Authorization Code + PKCE, ROPC, Refresh Token grants, MFA (TOTP + email OTP), WebAuthn/passkeys, SSO sessions, trusted devices, token introspection/revocation, and an embedded React admin UI.

## Quick Start

```bash
# Generate configuration
./autentico init --url https://auth.example.com

# Start the server
./autentico start
```

Or with Docker:

```bash
docker run --rm -v "$(pwd)":/output \
  ghcr.io/eugenioenko/autentico:latest \
  init --url https://auth.example.com --output /output

docker run \
  --name autentico \
  -p 9999:9999 \
  -v autentico-data:/data \
  --env-file .env \
  ghcr.io/eugenioenko/autentico:latest
```

## Documentation

Full documentation at [autentico.top](https://autentico.top)

## OIDC Conformance Testing

Autentico is tested against the [OpenID Foundation conformance suite](https://openid.net/certification/).

### Certified Profiles

| Profile | Status |
|---|---|
| Basic OP (`oidcc-basic-certification-test-plan`) | ✅ Passed |
| Comprehensive (`oidcc-test-plan`) | ✅ Passed |

### Running the Conformance Suite Locally

**1. Start the conformance suite:**

```bash
cd /tmp/conformance-suite && docker compose -f docker-compose-local.yml up -d
```

Suite UI available at **https://localhost:8444** (callbacks use port 8443 — both are exposed)

**2. Start Autentico in conformance mode** (in a terminal):

```bash
make conformance-server
```

This overrides `APP_URL=http://172.17.0.1:9999`, disables secure cookies and rate limiting so the suite can reach the server from inside Docker.

**3. Create conformance clients** (once, after onboarding):

```bash
TOKEN="<admin bearer token>"
REDIRECT="https://localhost.emobix.co.uk:8443/test/*/callback"

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"client_id\":\"openid1\",\"client_name\":\"Conformance Client 1\",\"client_secret\":\"openid1secret\",\"redirect_uris\":[\"$REDIRECT\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"scopes\":\"openid profile email offline_access address phone\",\"client_type\":\"confidential\",\"token_endpoint_auth_method\":\"client_secret_basic\"}"

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"client_id\":\"openid2\",\"client_name\":\"Conformance Client 2 (secret_post)\",\"client_secret\":\"openid2secret\",\"redirect_uris\":[\"$REDIRECT\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"scopes\":\"openid profile email offline_access address phone\",\"client_type\":\"confidential\",\"token_endpoint_auth_method\":\"client_secret_post\"}"

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"client_id\":\"openid3\",\"client_name\":\"Conformance Client 3\",\"client_secret\":\"openid3secret\",\"redirect_uris\":[\"$REDIRECT\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"scopes\":\"openid profile email offline_access address phone\",\"client_type\":\"confidential\",\"token_endpoint_auth_method\":\"client_secret_basic\"}"
```

| Role | client_id | client_secret | auth method |
|---|---|---|---|
| client | `openid1` | `openid1secret` | `client_secret_basic` |
| client_secret_post | `openid2` | `openid2secret` | `client_secret_post` |
| client2 | `openid3` | `openid3secret` | `client_secret_basic` |

**4. Configure the test plan:**

- Discovery URL: `http://172.17.0.1:9999/oauth2/.well-known/openid-configuration`
- Set alias to `conformance` (optional — the callback URL uses a dynamic run ID regardless)
- Access the admin UI at **http://localhost:9999/admin** (not `172.17.0.1` — browser blocks `Crypto.subtle` on non-localhost HTTP)
