# Security Test Plan: Account API Authorization and Session Management

## Target
`/account/api/*`, `/oauth2/logout` — `http://localhost:9999`

## Context from Proxy Traffic
Account API uses Bearer token auth for user self-service operations. Observed endpoints:

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | /account/api/profile | 200 | Get own profile |
| PUT | /account/api/profile | 200 | Update own profile |
| GET | /account/api/mfa | 200 | MFA status |
| POST | /account/api/mfa/totp/setup | 200 | Start TOTP enrollment |
| GET | /account/api/passkeys | 200 | List passkeys |
| POST | /account/api/passkeys/register/begin | 200 | Start passkey registration |
| GET | /account/api/sessions | 200 | List own sessions |
| DELETE | /account/api/sessions/{id} | 200 | Revoke a session |
| GET | /account/api/trusted-devices | 200 | List trusted devices |
| GET | /account/api/deletion-request | 200 | Deletion request status |
| GET | /account/api/connected-providers | 200 | Linked identity providers |
| GET | /account/api/settings | 200 | Account settings |

### Session Cookie
```
autentico_idp_session=...; Path=/oauth2; HttpOnly; Secure; SameSite=Lax
```

## Tests

### 1. Horizontal Access — Other Users' Data (HIGH)
**Why:** Verify that account API endpoints are scoped to the authenticated user only.

- [ ] Use User A's token to access User B's session by ID: `DELETE /account/api/sessions/{user_b_session_id}`
- [ ] Check if session IDs are enumerable/predictable
- [ ] Use User A's token — does `/account/api/sessions` only show User A's sessions?

### 2. Session Management
**Why:** IdP sessions control SSO — weaknesses here affect all relying parties.

- [ ] After logout (`POST /oauth2/logout`), verify the IdP session cookie is cleared
- [ ] After logout, try using the old access token — should it still work until expiry?
- [ ] After deleting a session via account API, verify associated tokens are invalidated
- [ ] Check for session fixation — does the IdP session ID change after login?
- [ ] Test idle timeout — does the session expire after the configured idle period?

### 3. MFA Bypass Attempts (HIGH)
**Why:** MFA protects against credential compromise — bypasses are critical.

- [ ] Start TOTP setup (`POST /account/api/mfa/totp/setup`) — is the TOTP secret returned in the response visible to the agent?
- [ ] After MFA is enabled, attempt login without completing MFA challenge — can you reach `/account/api/profile`?
- [ ] Check if the trusted device cookie bypasses MFA — can it be forged?
- [ ] Enumerate MFA challenge codes (TOTP is 6 digits = 1M combinations)
- [ ] Check if MFA challenge has attempt limits and lockout

### 4. Profile Update Injection
**Why:** Profile fields may be reflected in tokens or rendered in admin UI.

- [ ] Update profile with XSS in `given_name`: `<img src=x onerror=alert(1)>`
- [ ] Update profile with very long values — check for truncation vs overflow
- [ ] Update profile with fields that shouldn't be user-editable: `"email_verified": true`, `"role": "admin"`
- [ ] Check if updated profile fields appear in the next access token or id_token

### 5. Account Deletion Flow
- [ ] Submit a deletion request — is it immediately executed or pending?
- [ ] Can a deleted/deactivated user's existing tokens still be used?
- [ ] Can a deleted user re-register with the same username/email?

## Key Proxy Flows
| Flow ID | Endpoint | Notes |
|---------|----------|-------|
| uqfbIV | PUT /account/api/profile | Profile update |
| bz79ai | POST /account/api/mfa/totp/setup | TOTP setup response |
| bJuCCI | DELETE /account/api/sessions/... | Session revocation |
| BCqSWS | POST /oauth2/logout | Logout flow |
| tf3AP7 | POST /account/api/passkeys/register/begin | Passkey registration |
