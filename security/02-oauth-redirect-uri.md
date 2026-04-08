# Security Test Plan: OAuth2 Redirect URI and Authorization Endpoint

## Target
`/oauth2/authorize`, `/oauth2/login`, `/oauth2/token` — `http://localhost:9999`

## Context from Proxy Traffic
The authorize endpoint accepts `redirect_uri` as a query parameter and validates it against registered client URIs. The login endpoint receives it as a form field and issues a 302 redirect with an authorization code.

### Observed Flow (authorize → login → callback)
```
GET /oauth2/authorize?client_id=autentico-account&redirect_uri=http://localhost:9999/account/callback&response_type=code&scope=openid+profile+email+offline_access&state=...&code_challenge=...&code_challenge_method=S256
POST /oauth2/login → 302 → /account/callback?code=...&state=...
POST /oauth2/token (code exchange with code_verifier)
```

### Registered Clients Observed
- `autentico-admin` → redirect_uri: `http://localhost:9999/admin/callback`
- `autentico-account` → redirect_uri: `http://localhost:9999/account/callback`
- `test1` (public) → redirect_uri: `http://localhost:9090/callback`

## Tests

### 1. Open Redirect via redirect_uri (HIGH)
**Why:** If redirect_uri validation is weak, an attacker can steal authorization codes by redirecting to their own server.

- [ ] Exact match bypass: `redirect_uri=http://localhost:9999/account/callback/../evil`
- [ ] Subdomain/path tricks: `redirect_uri=http://localhost:9999/account/callbackevil`
- [ ] URL encoding bypass: `redirect_uri=http://localhost:9999/account/callback%00@evil.com`
- [ ] Scheme switch: `redirect_uri=https://localhost:9999/account/callback` (http→https)
- [ ] Port manipulation: `redirect_uri=http://localhost:9998/account/callback`
- [ ] Fragment injection: `redirect_uri=http://localhost:9999/account/callback#evil`
- [ ] Multiple redirect_uri params: `redirect_uri=legit&redirect_uri=evil`
- [ ] Unicode/homoglyph in redirect_uri
- [ ] Completely unregistered redirect_uri with valid client_id

### 2. Authorization Code Injection (MEDIUM)
**Why:** If PKCE is not strictly enforced, stolen codes can be exchanged by attackers.

- [ ] Exchange a code WITHOUT code_verifier — should fail if PKCE was used in authorize
- [ ] Exchange a code with wrong code_verifier — should fail
- [ ] Request authorize WITHOUT code_challenge — does the server allow non-PKCE flows?
- [ ] Replay a used authorization code — should fail (single-use)
- [ ] Use code from one client_id with another client_id at token endpoint

### 3. State Parameter Validation
**Why:** Missing or weak state validation enables CSRF on the OAuth flow.

- [ ] Authorize request without `state` parameter — should still work per spec but client should validate
- [ ] Check if the server validates state or just passes it through (server-side state validation is unusual but worth checking)

### 4. Scope Escalation
**Why:** An attacker may request scopes beyond what the client is authorized for.

- [ ] Request `scope=openid profile email offline_access admin` — does it grant extra scopes?
- [ ] Request scope not registered for the client
- [ ] Check if token response `scope` matches what was requested vs what was granted

### 5. Client Impersonation
**Why:** Public clients have no secret — test if confidential client flows can be downgraded.

- [ ] Use `autentico-admin` (confidential) client_id without client_secret at token endpoint
- [ ] Use `autentico-account` client_id with a different redirect_uri

## Key Proxy Flows
| Flow ID | Endpoint | Notes |
|---------|----------|-------|
| 8nQpRc | GET /oauth2/authorize | Account client authorize |
| UFlhwH | GET /oauth2/authorize | Admin client authorize |
| aDCGbE | POST /oauth2/login | Login redirect with code |
| F8Brfr | POST /oauth2/token | Code exchange with PKCE |
| wMrOa3 | GET /account/callback | Callback with code + state |
