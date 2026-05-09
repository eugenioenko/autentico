# Implementation Plan: Device Authorization Grant (RFC 8628)

## Overview

The Device Authorization Grant is designed for devices that lack a browser or have constrained input (smart TVs, CLI tools, IoT devices). The flow:

1. **Device requests authorization**: POST to device authorization endpoint with `client_id` and `scope`. Server responds with `device_code`, `user_code`, `verification_uri`, and `interval`.
2. **User authorizes on a separate device**: User visits `verification_uri`, enters `user_code`, authenticates, and approves.
3. **Device polls for tokens**: Device polls token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Server responds with `authorization_pending` until user completes authorization.

Key error responses during polling:
- `authorization_pending` — user has not yet authorized
- `slow_down` — device is polling too fast (adds 5 seconds to interval)
- `expired_token` — the device code has expired
- `access_denied` — user denied the request

## New Files

### 1. `pkg/devicecode/model.go`

```go
DeviceCode struct:
  Code            string    // high-entropy opaque device_code
  UserCode        string    // 8 chars, human-friendly uppercase letters
  ClientID        string
  Scope           string
  ExpiresAt       time.Time // default 600s, configurable
  Interval        int       // polling interval in seconds, default 5
  UserID          *string   // NULL until user authorizes
  Status          string    // "pending", "authorized", "denied", "expired"
  LastPolledAt    *time.Time
  CreatedAt       time.Time
```

Response struct per RFC 8628 section 3.2:
```go
DeviceAuthorizationResponse struct:
  DeviceCode              string `json:"device_code"`
  UserCode                string `json:"user_code"`
  VerificationURI         string `json:"verification_uri"`
  VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
  ExpiresIn               int    `json:"expires_in"`
  Interval                int    `json:"interval,omitempty"`
```

### 2. `pkg/devicecode/create.go`
- `CreateDeviceCode(dc DeviceCode) error`

### 3. `pkg/devicecode/read.go`
- `DeviceCodeByCode(code string) (*DeviceCode, error)` — lookup by device_code (polling)
- `DeviceCodeByUserCode(userCode string) (*DeviceCode, error)` — lookup by user_code (verification)

### 4. `pkg/devicecode/update.go`
- `AuthorizeDeviceCode(userCode string, userID string) error`
- `DenyDeviceCode(userCode string) error`
- `UpdateLastPolledAt(code string, t time.Time) error`

### 5. `pkg/devicecode/service.go`
- `GenerateDeviceCode() string` — 160+ bits of entropy (RFC 8628 section 6.1)
- `GenerateUserCode() string` — 8-character code using consonants only (`BCDFGHJKLMNPQRSTVWXZ`), displayed with hyphen (e.g., `ABCD-EFGH`)

### 6. `pkg/devicecode/handler.go`

**`HandleDeviceAuthorization`** — `POST /oauth2/device`
- Parses `client_id` and `scope` from form body
- Validates client exists and has `urn:ietf:params:oauth:grant-type:device_code` grant type
- Generates device_code and user_code, stores in DB
- Returns `DeviceAuthorizationResponse`

**`HandleDeviceVerification`** — `GET /oauth2/device/verify`
- Renders user verification HTML page
- Pre-fills user_code from `?user_code=...` (supports `verification_uri_complete`)

**`HandleDeviceVerificationSubmit`** — `POST /oauth2/device/verify`
- If not authenticated: redirect to login flow with return-to device verify
- If authenticated: validate user_code, show approval page, handle authorize/deny

### 7. `view/device_verify.html`
User code input form. CSRF protected.

### 8. `view/device_confirm.html`
Scope approval page (similar to consent.html). Authorize/Deny buttons.

### 9. `pkg/db/migrations/008_device_codes.go`

```sql
CREATE TABLE IF NOT EXISTS device_codes (
    code TEXT PRIMARY KEY,
    user_code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    last_polled_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);
```

## Existing Files to Modify

| File | Change |
|------|--------|
| `pkg/db/migrations/migrations.go` | Increment `SchemaVersion` to 8, add migration |
| `pkg/token/model.go` | Add `urn:ietf:params:oauth:grant-type:device_code` to validation, add `DeviceCode` field |
| `pkg/token/handler.go` | New case for device_code grant: check expiry, rate limiting, status, issue tokens |
| `pkg/client/model.go` | Allow `urn:ietf:params:oauth:grant-type:device_code` in grant_types validation |
| `pkg/wellknown/handler.go` | Add `DeviceAuthorizationEndpoint`, add grant type to `GrantTypesSupported` |
| `pkg/model/well_known_config.go` | Add `DeviceAuthorizationEndpoint string` field |
| `pkg/cli/start.go` | Register routes: `POST /device`, `GET /device/verify`, `POST /device/verify` |
| `pkg/cleanup/service.go` | Add `device_codes` to `transientTables` |
| `pkg/config/config.go` | Add `DeviceCodeExpiration` (default 600s), `DeviceCodePollingInterval` (default 5) |
| `pkg/appsettings/load.go` | Add defaults for device code settings |
| `tests/security/security_oauth2_test.go` | Remove device_code from unsupported grant types |

## API Endpoints

### `POST /oauth2/device` — Device Authorization

**Request** (form-encoded): `client_id` (required), `scope` (optional)

**Response** (200 OK):
```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://example.com/oauth2/device/verify",
  "verification_uri_complete": "https://example.com/oauth2/device/verify?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

### `POST /oauth2/token` — Device Code Token Exchange

**Request**: `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`

**Error responses** (HTTP 400): `authorization_pending`, `slow_down`, `expired_token`, `access_denied`

## User Verification Flow

1. User visits `/oauth2/device/verify` → sees user_code input form
2. User submits user_code → server validates
3. If NOT authenticated: redirect to login with return-to device verify
4. If authenticated: show confirmation page with client name and scopes
5. User clicks Authorize/Deny → server updates device code status

## Implementation Order

1. Database migration + model
2. Data layer (service, create, read, update)
3. Device authorization endpoint + routes
4. Token endpoint integration (polling grant type)
5. User verification UI (templates + handlers)
6. Discovery + cleanup
7. Tests (unit, handler, E2E, security)
8. Documentation

## Security Considerations (RFC 8628 Section 5)

- **User code entropy**: 20-char alphabet, 8 chars = ~34.6 bits (adequate for user-facing codes)
- **Device code entropy**: 160+ bits via `crypto/rand`
- **Rate limiting**: Enforce `interval` param, return `slow_down` + increment by 5s
- **Code expiry**: Default 10 min, expired codes never exchangeable
- **One-time use**: Consumed device codes marked as used
- **CSRF**: Verification pages use `csrfProtected` middleware
- **Scope validation**: Same rules as other grant types

## Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `device_code_expiration` | duration | `600s` | How long device codes remain valid |
| `device_code_polling_interval` | int | `5` | Minimum polling interval in seconds |

## Test Strategy

- **Unit**: code generation, DB operations, validation, status transitions
- **Token handler**: authorization_pending, slow_down, expired_token, access_denied, success
- **Handler**: device authorization, verification page, authorize/deny
- **E2E**: full device flow, denied flow, expired code, rate limiting
- **Security**: update rejected grant types list
