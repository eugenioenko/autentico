# Implementation Plan: Claims Request Parameter (OIDC Core SS5.5)

## Overview

The `claims` request parameter allows Relying Parties to request specific individual claims, rather than relying solely on scope values. Key aspects:

**Request format**: JSON object with two optional top-level members:
- `userinfo` — claims to return from the UserInfo endpoint
- `id_token` — claims to return in the ID Token

Each individual claim can be:
- `null` — voluntary claim, default behavior
- A JSON object with: `essential` (bool), `value` (specific value), `values` (set of values)

**Interaction with scopes**: Additive — claims requested via `claims` are added to scope-based claims.

**Error behavior**: The OP MUST NOT error when claims are unavailable (SS5.5.1). Exception: `sub` with `value` constraint — a mismatch MUST cause authentication to fail.

## Claims Autentico Can Fulfill

| Claim | Source Field | Scope |
|-------|-------------|-------|
| `sub` | `ID` | always |
| `name` | `Username` / GivenName + FamilyName | profile |
| `preferred_username` | `Username` | profile |
| `given_name` | `GivenName` | profile |
| `family_name` | `FamilyName` | profile |
| `middle_name` | `MiddleName` | profile |
| `nickname` | `Nickname` | profile |
| `profile` | `ProfileURL` | profile |
| `picture` | `Picture` | profile |
| `website` | `Website` | profile |
| `gender` | `Gender` | profile |
| `birthdate` | `Birthdate` | profile |
| `locale` | `Locale` | profile |
| `zoneinfo` | `Zoneinfo` | profile |
| `updated_at` | `UpdatedAt` | profile |
| `email` | `Email` | email |
| `email_verified` | `IsEmailVerified` | email |
| `phone_number` | `PhoneNumber` | phone |
| `phone_number_verified` | `PhoneNumberVerified` | phone |
| `address` | Address fields | address |
| `groups` | via `group.GroupNamesByUserID()` | groups |

## Design Decisions

1. **Claims parameter stored as opaque JSON string.** Stored as-is in `auth_codes` and `tokens` tables. Parsed at consumption time (ID token generation and userinfo response).

2. **No new configuration.** Feature is always enabled. Only change is `claims_parameter_supported: true` in discovery.

3. **Essential claims are best-effort.** Per SS5.5.1, the OP MUST NOT error when claims are unavailable. Essential is treated identically to voluntary.

4. **`sub` value constraint enforcement.** If `claims.id_token.sub.value` is specified and doesn't match the authenticated user, authentication MUST fail (checked at auth code creation time).

## New Files

### 1. `pkg/claims/claims.go`

```go
type ClaimsRequest struct {
    UserInfo map[string]*ClaimRequest `json:"userinfo,omitempty"`
    IDToken  map[string]*ClaimRequest `json:"id_token,omitempty"`
}

type ClaimRequest struct {
    Essential bool          `json:"essential,omitempty"`
    Value     interface{}   `json:"value,omitempty"`
    Values    []interface{} `json:"values,omitempty"`
}

func Parse(raw string) (*ClaimsRequest, error)
func IsClaimRequested(target map[string]*ClaimRequest, claimName string) bool
func GetRequestedClaimNames(target map[string]*ClaimRequest) []string
```

Validation: valid JSON, object at top level, unknown members ignored, 4KB size limit.

### 2. `pkg/db/migrations/008_claims_parameter.go`

```sql
ALTER TABLE auth_codes ADD COLUMN claims TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN claims TEXT NOT NULL DEFAULT '';
```

## Files to Modify

### Data Layer

| File | Change |
|------|--------|
| `pkg/db/migrations/migrations.go` | Increment `SchemaVersion`, add migration |
| `pkg/auth_code/model.go` | Add `Claims string` field |
| `pkg/auth_code/create.go` | Add `claims` to INSERT |
| `pkg/auth_code/read.go` | Add `claims` to SELECT + scan |
| `pkg/token/model.go` | Add `Claims string` to `Token` struct |
| `pkg/token/create.go` | Add `claims` to INSERT |
| `pkg/token/read.go` | Add `claims` to SELECT + scan |

### Authorization Flow (threading `claims` through all code paths)

| File | Change |
|------|--------|
| `pkg/authorize/model.go` | Add `Claims string` to `AuthorizeRequest` |
| `pkg/authorize/handler.go` | Parse `claims`, validate JSON, pass through to auth code |
| `pkg/authzsig/authzsig.go` | Add `Claims string` to `AuthorizeParams` |
| `pkg/login/model.go` | Add `Claims string` to `LoginRequest` |
| `pkg/login/handler.go` | Read `claims` from form, sub value constraint check, pass to auth code |
| `pkg/consent/handler.go` | Add `Claims` to `ConsentParams`, pass through |
| `pkg/mfa/model.go` | Add `Claims` to `LoginState` |
| `pkg/mfa/handler.go` | Pass `Claims` to auth code |
| `pkg/passkey/model.go` | Add `Claims` to `LoginState` / `RegistrationState` |
| `pkg/passkey/handler.go` | Pass `Claims` to auth code |
| `pkg/signup/handler.go` | Add `Claims` to `SignupParams`, pass through |
| `pkg/federation/model.go` | Add `Claims` to `FederationState` |
| `pkg/emailverification/handler.go` | Add `Claims` to `OAuthParams` |

### Templates

| File | Change |
|------|--------|
| `view/login.html` | Hidden input for `claims`, update links |
| `view/consent.html` | Hidden input for `claims` |
| `view/signup.html` | Hidden input for `claims` |

### Token Generation

| File | Change |
|------|--------|
| `pkg/token/generate.go` | Accept `claimsParam string`, parse it, add requested claims to ID token |
| `pkg/token/handler.go` | Read `claims` from auth code, store in token record, pass to `GenerateIDToken`. Carry forward on refresh. |

### UserInfo

| File | Change |
|------|--------|
| `pkg/userinfo/handler.go` | Read `claims` from token record, apply `claims.userinfo` to response |

### Discovery

| File | Change |
|------|--------|
| `pkg/model/well_known_config.go` | Add `ClaimsParameterSupported bool` field |
| `pkg/wellknown/handler.go` | Set `ClaimsParameterSupported: true` |

## Refresh Token Flow

When a refresh token is used, the new ID token must respect the original `claims` request. The `claims` value is stored in the `tokens` table alongside scope. The refresh flow reads `tokenClaims` from the old token and passes it to `GenerateIDToken`.

## Implementation Order

1. `pkg/claims/claims.go` + tests — parse/validate claims JSON (no dependencies)
2. Database migration — add `claims` column to `auth_codes` and `tokens`
3. Auth code model + CRUD — add `Claims` field
4. Token model + CRUD — add `Claims` field
5. Authorization signature — add `Claims` to `AuthorizeParams`
6. Authorize endpoint — parse, validate, pass through
7. View templates — hidden `claims` fields
8. Login handler — read from form, sub constraint check
9. All other handlers (consent, MFA, passkey, signup, federation, email verification) — thread `Claims` through
10. Token generation — apply claims parameter
11. Token handler — read from auth code, store in token, carry forward on refresh
12. UserInfo handler — apply `claims.userinfo`
13. Discovery document — `claims_parameter_supported: true`
14. Tests + documentation

## Challenges

**A. Threading through many code paths.** 7 distinct locations create `AuthCode` structs. Each change is mechanical but must not be missed.

**B. UserInfo access to claims.** The UserInfo endpoint operates on the access token, not the auth code. Storing `claims` in the `tokens` table keeps the implementation clean.

**C. Template HTML encoding.** The `claims` JSON in hidden form fields is auto-escaped by `html/template`. URL query strings in links need `{{.Claims | urlquery}}`.

**D. Claims parameter size.** Add a 4KB limit during validation to prevent abuse.

**E. Refresh token carry-forward.** Stored in `tokens` table alongside scope.

## Test Strategy

### Unit Tests
- `pkg/claims/claims_test.go` — parse valid/invalid JSON, null values, essential/value/values, unknown members
- `pkg/token/generate_test.go` — claims parameter adds claims, additive with scope, value constraints, sub mismatch

### E2E Tests
- `tests/e2e/claims_parameter_test.go` — full auth code flow with claims parameter, verify ID token and UserInfo both return requested claims, additive behavior

### Negative Tests
- Invalid JSON → `invalid_request`
- Essential claim user doesn't have → simply omitted (no error)
- `sub` value mismatch → authentication fails
