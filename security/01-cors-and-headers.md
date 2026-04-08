# Security Test Plan: CORS, CSP, and HTTP Security Headers

## Target
Autentico OAuth2/OIDC Identity Provider — `http://localhost:9999`

## Context from Proxy Traffic
All observed responses include `Access-Control-Allow-Origin: *` — including sensitive endpoints like `/oauth2/token`, `/oauth2/login`, `/admin/api/*`, and `/account/api/*`. This is the highest-priority finding to validate.

### Observed Headers (from flow aDCGbE — POST /oauth2/login)
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; form-action 'self'; frame-ancestors 'none'
Cross-Origin-Embedder-Policy: credentialless
Cross-Origin-Opener-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

## Tests

### 1. CORS Wildcard on Sensitive Endpoints (LOW — by design)
**Status:** The wildcard `Access-Control-Allow-Origin: *` is intentional for local dev. It's controlled by `AUTENTICO_APP_ENABLE_CORS=true` in `.env` (see `pkg/middleware/cors.go`). In production, this should be `false` with a reverse proxy handling CORS. The middleware does NOT set `Access-Control-Allow-Credentials`, so cookies are not sent cross-origin.

- [ ] Verify `Access-Control-Allow-Credentials` is NOT set (confirmed — not present in traffic)
- [ ] With CORS disabled (`AUTENTICO_APP_ENABLE_CORS=false`), confirm no CORS headers are sent
- [ ] Document: production deployment MUST either disable this or use a reverse proxy with proper origin restrictions

### 2. CORS + Cookie Interaction
**Why:** `SameSite=Lax` on `autentico_idp_session` blocks cross-origin POST cookies, but GET requests with cookies may still work.

- [ ] Cross-origin GET to `/oauth2/authorize` — does the IdP session cookie get sent? (SameSite=Lax allows top-level navigations)
- [ ] Cross-origin POST to `/oauth2/token` — cookies should be blocked by SameSite=Lax
- [ ] Test if admin API Bearer token auth is affected (Bearer tokens aren't auto-sent, so CORS `*` is lower risk here)

### 3. CSP Validation
**Why:** CSP looks solid but should be tested for bypasses.

- [ ] Confirm `frame-ancestors 'none'` blocks framing (clickjacking protection)
- [ ] Check if `'unsafe-inline'` in `style-src` can be leveraged (low risk but worth noting)
- [ ] Verify `form-action 'self'` prevents form submissions to external origins
- [ ] Check if CSP is present on error pages and non-HTML responses

### 4. Missing Headers Check
- [ ] Check for `Strict-Transport-Security` header (should be present in production)
- [ ] Verify `Cache-Control: no-store` on token responses (observed on `/oauth2/token` — good)
- [ ] Check if `Cache-Control: no-store` is set on `/oauth2/authorize`, `/oauth2/login`, and other auth-flow pages
- [ ] Verify `Referrer-Policy` header is set (not observed in traffic)

### 5. COEP/COOP Interaction
- [ ] Verify `Cross-Origin-Embedder-Policy: credentialless` doesn't interfere with legitimate cross-origin resource loading
- [ ] Confirm `Cross-Origin-Opener-Policy: same-origin` isolates the browsing context

## Key Proxy Flows for Reference
| Flow ID | Endpoint | Notes |
|---------|----------|-------|
| aDCGbE | POST /oauth2/login | Login with CORS headers visible |
| F8Brfr | POST /oauth2/token | Token exchange with CORS `*` |
| kxP3jL | POST /admin/api/clients | Admin API with CORS `*` |
| UFlhwH | GET /oauth2/authorize | Authorize endpoint headers |
