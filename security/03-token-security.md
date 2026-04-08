# Security Test Plan: Token Security and JWT Validation

## Target
`/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, `/oauth2/userinfo` — `http://localhost:9999`

## Context from Proxy Traffic

### Access Token (RS256, 15min expiry)
```json
Header: {"alg": "RS256", "kid": "autentico-key-1", "typ": "JWT"}
Payload: {
  "acr": "1", "aud": [], "auth_time": 1775600770,
  "azp": "autentico-account", "email": "", "email_verified": false,
  "exp": 1775601670, "iss": "http://localhost:9999/oauth2",
  "jti": "d7ao90lioaq9lf9ssp9g", "name": "test1",
  "scope": "openid profile email offline_access",
  "sid": "d7ao90lioaq9lf9ssp90", "sub": "d7ao2slioaq9lf9sskng", "typ": "Bearer"
}
```

### Refresh Token (HS256, ~30 day expiry)
```json
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {
  "azp": "autentico-account", "exp": 1778192770,
  "iat": 1775600770, "sid": "d7ao90lioaq9lf9ssp90",
  "sub": "d7ao2slioaq9lf9sskng"
}
```

## Tests

### 1. JWT Algorithm Confusion (HIGH)
**Why:** If the server accepts `alg: none` or `alg: HS256` for access tokens (normally RS256), an attacker can forge tokens.

- [ ] Craft a token with `"alg": "none"` and no signature — send to `/oauth2/userinfo`
- [ ] Craft a token with `"alg": "HS256"` using the public key as HMAC secret — send to `/oauth2/userinfo`
- [ ] Craft a token with `"alg": "RS384"` or `"alg": "RS512"` — check if alternative RSA algorithms are accepted
- [ ] Send a token with modified `kid` header — does it cause an error or key confusion?

### 2. Access Token with Empty Audience (MEDIUM)
**Why:** The access token has `"aud": []` — an empty audience array. This means audience validation may be skipped, allowing the token to be accepted by unintended resource servers.

- [ ] Check if the `/oauth2/userinfo` endpoint validates the `aud` claim
- [ ] Check if admin API validates audience or just checks for valid signature + authorized user
- [ ] Request a token for a client with `allowed_audiences` set — verify `aud` is populated

### 3. Refresh Token Abuse
**Why:** Refresh tokens are long-lived (~30 days) and use HS256. Test rotation and revocation.

- [ ] Use a refresh token twice — does the server implement rotation (invalidate old token)?
- [ ] Revoke a refresh token via `/oauth2/revoke`, then try to use it
- [ ] Use a refresh token from client A with client B's credentials
- [ ] Check if refresh token grants a new refresh token (token chain)

### 4. Token Revocation Completeness
- [ ] Revoke an access token via `/oauth2/revoke` — is it immediately rejected at `/oauth2/userinfo`?
- [ ] Revoke a refresh token — can the associated access token still be used until expiry?
- [ ] Logout via `/oauth2/logout` — are all tokens for the session invalidated?
- [ ] Delete a session via account API — are associated tokens revoked?

### 5. Token Introspection
- [ ] Call `/oauth2/introspect` with a valid token — check response format
- [ ] Call `/oauth2/introspect` with an expired token — should return `active: false`
- [ ] Call `/oauth2/introspect` with a revoked token
- [ ] Call `/oauth2/introspect` without client authentication — should it require auth?

### 6. Token Endpoint Grant Types
- [ ] Test ROPC (password grant) — `grant_type=password` with username/password directly
- [ ] Test client_credentials grant — does it return tokens without user context?
- [ ] Send unsupported grant_type — verify proper error response

## Key Proxy Flows
| Flow ID | Endpoint | Notes |
|---------|----------|-------|
| F8Brfr | POST /oauth2/token | Code exchange — has both tokens |
| kGh5KR | POST /oauth2/token | Admin token exchange |
| gW2tDX | GET /oauth2/userinfo | Userinfo with Bearer token |
