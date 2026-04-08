# Security Test Plan: Login Security, Brute Force, and CSRF

## Target
`/oauth2/login`, `/oauth2/authorize`, CSRF protection — `http://localhost:9999`

## Context from Proxy Traffic

### Login Request (flow aDCGbE)
```
POST /oauth2/login
Content-Type: application/x-www-form-urlencoded
Cookie: _gorilla_csrf=...

gorilla.csrf.Token=...&state=...&redirect_uri=...&client_id=...&scope=...
&nonce=&code_challenge=...&code_challenge_method=S256
&username=test1&password=asdf123
```

CSRF protection uses gorilla/csrf: a `_gorilla_csrf` cookie + `gorilla.csrf.Token` form field.

## Tests

### 1. Credential Brute Force (HIGH)
**Why:** Login endpoint accepts username+password — must have rate limiting and lockout.

- [ ] Send 20+ rapid login attempts with wrong password for same user — check for rate limiting or lockout
- [ ] After lockout (if any), check the error message — does it reveal that the account exists?
- [ ] Test with a non-existent username — does the error message differ from wrong password? (username enumeration)
- [ ] Check timing difference between valid-user-wrong-password vs invalid-user (timing oracle)

### 2. CSRF Protection (MEDIUM)
**Why:** gorilla/csrf protects form submissions — verify coverage and strength.

- [ ] Submit login form without `gorilla.csrf.Token` — should be rejected
- [ ] Submit login form without `_gorilla_csrf` cookie — should be rejected
- [ ] Submit login form with mismatched cookie and token — should be rejected
- [ ] Check if CSRF token is single-use or replayable
- [ ] Verify CSRF protection on `POST /oauth2/logout` — is logout CSRF-protected?
- [ ] Check if JSON API endpoints (`/admin/api/*`, `/account/api/*`) need CSRF tokens or rely on Bearer auth only

### 3. Credential Exposure
**Why:** Credentials should not leak through logs, errors, or responses.

- [ ] Submit login with wrong credentials — does the error response include the password?
- [ ] Check if the login form action URL includes sensitive parameters
- [ ] Verify `Cache-Control: no-store` on the login page to prevent caching credentials
- [ ] Check Referrer header after login redirect — does it leak credentials in the URL?

### 4. Username Enumeration
**Why:** Different error messages for valid vs invalid usernames leak information.

- [ ] Login with valid username, wrong password — note exact error message
- [ ] Login with non-existent username — note exact error message
- [ ] Check `/oauth2/signup` (if enabled) — does it reveal existing usernames?
- [ ] Check password reset flow (if any) — does it reveal existing email addresses?

### 5. Password Policy
- [ ] Create a user with a 1-character password — is it accepted?
- [ ] Create a user with common passwords (password123, admin, etc.)
- [ ] Update password via account API — same policy checks?

### 6. Login Flow Parameter Tampering
**Why:** Login form contains hidden fields from the authorize request that get passed through.

- [ ] Modify `client_id` in the login POST body to a different client
- [ ] Modify `redirect_uri` in the login POST body (differs from what was validated at /authorize)
- [ ] Modify `scope` in the login POST body to escalate permissions
- [ ] Remove `code_challenge` from login POST — does it issue a code without PKCE?

## Key Proxy Flows
| Flow ID | Endpoint | Notes |
|---------|----------|-------|
| aDCGbE | POST /oauth2/login | Login with credentials + CSRF |
| KNIm2v | POST /oauth2/login | Second login (admin) |
| BCqSWS | POST /oauth2/logout | Logout POST |
| 8nQpRc | GET /oauth2/authorize | Authorize renders login form |
