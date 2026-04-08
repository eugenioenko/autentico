# Autentico Application Security Testing Report

**Date:** 2026-04-07
**Target:** Autentico OAuth2/OIDC Identity Provider — `http://localhost:9999`
**Tool:** sectool (go-appsec/toolbox v0.1.11) + Claude Code
**Status:** Complete (autonomous tests) — interactive tests pending

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 2 |
| **Total** | **5** |
| Passed Tests | 23 |

---

## Findings

### FINDING-01: PKCE Not Enforced at Authorization Endpoint (MEDIUM)
**Endpoint:** `GET /oauth2/authorize`
**Description:** The authorize endpoint accepts requests without `code_challenge` and `code_challenge_method` parameters, rendering the login form with empty hidden fields for these values. This means a non-PKCE authorization code flow is permitted.
**Impact:** Without PKCE, authorization codes intercepted in transit (e.g., via referrer leakage or open redirect) can be exchanged by an attacker without needing the code verifier. Public clients (like SPAs) are especially vulnerable.
**Evidence:** Replayed flow `4q2mFx` — removed `code_challenge` and `code_challenge_method` from authorize request → 200 OK, login form rendered with `<input type="hidden" name="code_challenge" value="" />`.
**Status:** Partially confirmed — authorize allows non-PKCE flows. Token endpoint enforcement not yet tested (requires browser-based login to generate a non-PKCE auth code).
**Recommendation:** Enforce PKCE for all clients, or at minimum for public clients. Reject authorize requests without `code_challenge` for public clients per RFC 7636 / OAuth 2.1 draft.

### FINDING-02: Token Introspection Endpoint Accepts Unauthenticated Requests (HIGH)
**Endpoint:** `POST /oauth2/introspect`
**Description:** The introspection endpoint returns full token details for active tokens without requiring client authentication. No `Authorization` header or `client_id`/`client_secret` in the body is needed.
**Impact:** Per RFC 7662 Section 2.1, the introspection endpoint SHOULD require client authentication. Without it, any party can determine whether arbitrary tokens are active and extract token metadata (subject, scope, issuer, expiry). This aids token reconnaissance and abuse.
**Evidence:**
- Flow `YowO0B` — expired token, no client auth → 200 `{"active":false}`
- Flow `LkcL1P` — valid token, no client auth → 200 `{"active":true,"scope":"openid profile email","token_type":"Bearer","exp":...,"sub":"d7a25htioaqe2mcpo490","iss":"http://localhost:9999/oauth2",...}`
**Status:** Confirmed — both expired and active tokens introspectable without authentication.
**Recommendation:** Require client authentication (Basic auth or `client_id`/`client_secret` in body) for introspection requests.

### FINDING-03: CSRF Error Message Leaks Configuration Details (LOW)
**Endpoint:** All CSRF-protected endpoints
**Description:** When a POST request is made without a valid CSRF cookie, the error message reveals internal configuration: `"Forbidden - CSRF token invalid: referer not supplied (AUTENTICO_CSRF_SECURE_COOKIE=true but request is HTTP — cookie was not sent)"`.
**Impact:** Information disclosure — reveals environment variable names and values to unauthenticated users. Aids attacker reconnaissance.
**Evidence:** Flows `xaZvfC`, `MqIC88` — POST to `/oauth2/login` without CSRF cookie → 403 with verbose error.
**Recommendation:** Return a generic CSRF error message (e.g., "Forbidden - invalid CSRF token") without exposing configuration internals.

### FINDING-04: Refresh Token Not Rotated on Use (MEDIUM)
**Endpoint:** `POST /oauth2/token` (grant_type=refresh_token)
**Description:** When a refresh token is used to obtain new access tokens, the same refresh token remains valid and can be reused indefinitely. No new refresh token is issued on each use.
**Impact:** If a refresh token is compromised, the attacker can use it alongside the legitimate user without detection. Token rotation (issuing a new refresh token and invalidating the old one on each use) is recommended by OAuth 2.0 Security Best Current Practice (RFC 6819) and required by OAuth 2.1 draft.
**Evidence:** Flow `sm4tiL` — first refresh → 200 with new access token. Flow `pdxk16` — same refresh token reused → 200 with another new access token. Both succeeded.
**Status:** Confirmed.
**Recommendation:** Implement refresh token rotation — issue a new refresh token on each use and invalidate the previous one. Consider also implementing replay detection (if a rotated-out token is used, revoke the entire token family).

### FINDING-05: XSS Payload Stored in Client Name (LOW)
**Endpoint:** `POST /admin/api/clients`
**Description:** The admin API accepts HTML/script content in the `client_name` field without sanitization. The value `<script>alert('xss')</script>` was stored successfully.
**Impact:** The stored XSS payload is JSON-encoded in API responses (`\u003cscript\u003e`) and does NOT render in the server-side login page template (client_name not displayed on authorize page). The admin UI is a React SPA which escapes output by default. Risk is low but defense-in-depth suggests sanitizing input.
**Evidence:** Flow `u4Tf3z` — created client with `client_name: "<script>alert('xss')</script>"` → 201 Created. Flow `pWYA2v` — authorize page for this client does not render client_name in HTML.
**Status:** Confirmed stored, but no exploitable rendering context found.
**Recommendation:** Sanitize or reject HTML characters in client_name at the API level as defense-in-depth.

---

## Passed Tests

### Redirect URI Validation — PASS
All redirect_uri manipulation attempts correctly rejected with 400:
- Completely unregistered URI (`https://evil.com/callback`)
- Path traversal (`/callback/../../../evil`)
- Userinfo bypass (`localhost:9999@evil.com/callback`)
- Suffix append (`/callbackevil`)
- Fragment injection (`/callback%23evil`)
- Protocol-relative (`//evil.com/callback`)

### Authorization Code Replay Protection — PASS
Replaying a used authorization code returns 400 `"Authorization code has already been used"`.

### JWT Algorithm Confusion (`alg: none`) — PASS
Token crafted with `"alg": "none"` and empty signature rejected at `/oauth2/userinfo` with 401 `"Token is invalid or expired"`.

### Scope Escalation — PASS
Adding unauthorized scope (`admin`) to login request rejected with 400 `"One or more requested scopes are not allowed for this client"`.

### Admin API Authorization — PASS
- No auth header → 401
- Non-admin user token → 403 `"Admin access required"`

### Username Enumeration — PASS
Both non-existent user and valid user with wrong password return identical 302 redirect with `error=Invalid+username+or+password`. No timing difference observed between the two requests (~55ms each).

### Dynamic Client Registration — PASS
`POST /oauth2/register` without authentication returns 401. Registration requires authorization.

### CORS Configuration — PASS (by design)
`Access-Control-Allow-Origin: *` is controlled by `AUTENTICO_APP_ENABLE_CORS=true` in `.env` (see `pkg/middleware/cors.go`). Intended for local dev; disabled in production via reverse proxy. No `Access-Control-Allow-Credentials` header set.

### Mass Assignment — PASS
Creating a user with extra fields (`"is_admin": true, "role": "admin"`) results in user created with `"role": "user"`. Extra fields are ignored.

### Redirect URI Scheme Validation — PASS
`javascript:alert(1)` as redirect_uri in client creation rejected with 400 `"Invalid redirect URI: must be a valid URL"`.

### Refresh Token Cross-Client Use — PASS
Using a refresh token issued to `autentico-admin` with `client_id=autentico-account` returns 400 `"Refresh token was not issued to this client"`.

### Token Revocation — PASS
`POST /oauth2/revoke` with a valid token returns 200 (empty body). Subsequent introspection of the same token returns `{"active": false}`.

### Password Policy — PASS
Creating a user with password `"a"` (1 char) rejected with 400 `"password is invalid: the length must be between 6 and 64"`.

### Account Lockout — PASS
After 5 failed login attempts (configurable via `account_lockout_max_attempts`, default 5), the account is locked for 15 minutes (`account_lockout_duration`). Error message changes from "Invalid username or password" to "Account is temporarily locked due to too many failed login attempts" — **minor caveat:** the lockout message confirms the account exists, unlike the generic login failure message. This is a minor username enumeration vector via brute-force (an attacker who hits the lockout threshold learns the account is real).

### Client Credentials Grant — PASS
`grant_type=client_credentials` with `autentico-admin` returns 400 `"Grant type not allowed for this client"`. Grant types are properly scoped per client registration.

### Post-Logout Redirect Validation — PASS
`POST /oauth2/logout` with `post_logout_redirect_uri=https://evil.com` does NOT redirect to the evil URL. The logout page renders a static "You have been signed out" page with a link back to `/account/`. The `post_logout_redirect_uri` parameter is ignored when not registered for the client. IdP session cookie is properly cleared with `Max-Age=0`.

### Error Parameter XSS — PASS
Injecting `<script>alert(1)</script>` via the `error` query parameter on `/oauth2/authorize` results in proper HTML encoding in the rendered page: `&lt;script&gt;alert(1)&lt;/script&gt;`. Go's `html/template` auto-escapes correctly.

### SQL Injection — PASS
SQLi payloads in multiple input vectors were stored as literal strings, not interpreted:
- Client ID: `sqli' OR '1'='1` → stored as literal string, 201 Created
- Username: `admin' OR '1'='1` → stored as literal string, 201 Created
- Query param: `offset=0;DROP TABLE users;--` → parsed as string, no SQL error
The application uses Go's `database/sql` with parameterized queries throughout (`modernc.org/sqlite` driver).

### Sensitive Data Exposure in API — PASS
Admin sessions endpoint (`/admin/api/sessions`) returns session metadata (user_agent, ip_address, timestamps) but does NOT expose password hashes, TOTP secrets, or other sensitive credential data.

### Missing Security Headers — INFORMATIONAL
The following headers are absent from all responses:
- **`Strict-Transport-Security`** — not set (expected for HTTP localhost, should be configured in production or at the reverse proxy level)
- **`Referrer-Policy`** — not set as HTTP header. The login page uses `<meta name="referrer" content="same-origin">` in HTML, which is good, but a response header would provide defense-in-depth
- **`Cache-Control`** — not set on `/oauth2/authorize` (login page) or `/.well-known/openid-configuration`. Present and correct (`no-store`) on `/oauth2/token` responses

---

## Not Yet Tested (require interactive browser sessions)
- [ ] PKCE enforcement at token endpoint (needs browser login without PKCE to capture non-PKCE auth code)
- [ ] Session fixation / IdP session ID change after login
- [ ] MFA bypass attempts (needs MFA enabled + interactive challenge flow)
- [ ] Horizontal access control on account API (needs two separate user sessions)
- [ ] SSRF via federation configuration (needs OAST URLs entered in admin UI)
- [ ] OAST-based out-of-band interaction testing

---

## Testing Methodology
- **Proxy capture:** sectool proxy on `127.0.0.1:8080`, Firefox configured to route `localhost` traffic through proxy (`network.proxy.allow_hijacking_localhost=true`)
- **Traffic analysis:** 112 proxy flows captured covering OAuth authorize/login/token, admin API CRUD, account API, and static assets
- **Replay testing:** Captured flows replayed with mutations via `sectool replay_send` and `request_send`
- **JWT analysis:** Access and refresh tokens decoded and analyzed for algorithm, claims, and expiry
- **Cookie analysis:** Session cookies inspected for security attributes (Secure, HttpOnly, SameSite)
