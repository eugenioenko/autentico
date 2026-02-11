# Autentico Test Coverage Completion Plan

## Current State

~180 tests across 54 files. Tests are mostly unit tests and handler-level integration tests using `httptest.NewRecorder()`. There is no true end-to-end test that starts a real HTTP server and exercises the complete OAuth2/OIDC flow with a real HTTP client handling cookies and redirects.

---

## Phase 1: Test Infrastructure and E2E Server Helper

**Goal:** Build the reusable test infrastructure that all subsequent phases depend on. Create a test server helper that replicates `main.go` routing so that true HTTP-level end-to-end tests can make real requests with cookie jars, redirects, and middleware.

### Files to create

**`tests/utils/test_server.go`**

Provides `StartTestServer(t *testing.T) *TestServer`. The `TestServer` struct wraps `httptest.Server` and provides:

- `Server *httptest.Server` — the actual test server
- `Client *http.Client` — configured with `http.CookieJar` and `CheckRedirect` set to not follow redirects (so tests can inspect 302 responses)
- `BaseURL string` — e.g., `http://127.0.0.1:<port>`
- `Close()` — shuts down the server and cleans database tables

The function should:

1. Call `db.InitTestDB()` to use fast in-memory SQLite database
2. Register all routes on `http.NewServeMux{}` exactly as `main.go` does, including CSRF middleware on `/oauth2/authorize` and `/oauth2/login`, `AdminAuthMiddleware` on `/oauth2/register`, and `LoggingMiddleware` wrapper
3. Override `config.Values` to point at the test server URL (issuer, host, etc.)
4. Start `httptest.NewServer(combinedMiddleware(mux))`
5. Register `t.Cleanup` to clean database tables (not close DB) and shutdown server

Additional helpers:

- `NewClientNoRedirect()` — returns a client that does NOT follow redirects
- `GetCSRFToken(authorizePageBody string) string` — parses the CSRF token from the rendered login HTML
- `CleanupTestDB()` — efficiently clears all tables using `DELETE FROM` statements for test isolation

**Database Strategy:**
Uses in-memory SQLite database (`:memory:`) for maximum speed. Between tests, tables are cleaned using `DELETE FROM` rather than recreating the entire database. This approach is:

- **Much faster** than file-based databases
- **Resource efficient** with single database instance
- **Parallel-safe** when properly implemented
- **Industry standard** for integration testing

**Note:** The existing `tests/utils/test_db.go` should also be updated to use in-memory database and table cleanup for consistency across all test types.

**`tests/utils/test_helpers.go`**

Higher-level helpers reused across E2E tests:

- `CreateTestUser(t, username, password, email) *user.UserResponse`
- `CreateTestAdmin(t, username, password, email) (*user.UserResponse, string)` — creates admin user + access token
- `CreateTestClient(t, req client.ClientCreateRequest) *client.ClientResponse`
- `ObtainTokensViaPasswordGrant(t, ts *TestServer, username, password string) *token.TokenResponse`
- `PerformAuthorizationCodeFlow(t, ts *TestServer, clientID, redirectURI, username, password, state string) (code string, cookies []*http.Cookie)` — drives the full authorize → login → extract code chain

### Tests to write

**`tests/e2e/server_test.go`**

| Test                                  | Validates                                                                                                                        |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `TestServerStarts`                    | Test server starts, `GET /.well-known/openid-configuration` returns 200 with valid JSON                                          |
| `TestServerJWKS`                      | `GET /.well-known/jwks.json` returns a valid JWK set with at least one key                                                       |
| `TestServerAuthorizeRendersLoginPage` | `GET /oauth2/authorize?response_type=code&redirect_uri=...&state=abc` returns 200 with HTML containing login form and CSRF token |

---

## Phase 2: Full Authorization Code Flow Chain

**Goal:** Test the complete authorization code flow as a single chain: authorize → login → token exchange → userinfo. This is the single highest-value test gap.

### File to create

**`tests/e2e/auth_code_flow_test.go`**

| Test                                             | Validates                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestAuthorizationCodeFlow_Complete`             | Full flow: (1) Create user. (2) GET /oauth2/authorize. (3) Parse CSRF token. (4) POST /oauth2/login with credentials + CSRF. (5) Verify 302 redirect with code= and state=. (6) POST /oauth2/token with grant_type=authorization_code. (7) Verify access_token and refresh_token returned. (8) GET /oauth2/userinfo with access_token. (9) Verify user info matches. |
| `TestAuthorizationCodeFlow_WithRegisteredClient` | Same flow with a registered confidential client. Token request includes client_id and client_secret via Basic Auth.                                                                                                                                                                                                                                                  |
| `TestAuthorizationCodeFlow_PublicClient`         | Same flow with a public client (no client_secret required at token exchange).                                                                                                                                                                                                                                                                                        |
| `TestAuthorizationCodeFlow_StatePreserved`       | State parameter sent to /authorize appears unmodified in redirect from /login.                                                                                                                                                                                                                                                                                       |
| `TestAuthorizationCodeFlow_CodeReuse`            | After exchanging a code, attempt same code again. Verify `invalid_grant`.                                                                                                                                                                                                                                                                                            |
| `TestAuthorizationCodeFlow_CodeExpiry`           | Create auth code with past expiry. Attempt exchange. Verify `invalid_grant`.                                                                                                                                                                                                                                                                                         |
| `TestAuthorizationCodeFlow_RedirectMismatch`     | Different redirect_uri in /authorize vs /token. Verify `invalid_grant`.                                                                                                                                                                                                                                                                                              |
| `TestAuthorizationCodeFlow_InvalidCSRF`          | POST to /oauth2/login without valid CSRF token. Verify 403 Forbidden.                                                                                                                                                                                                                                                                                                |

---

## Phase 3: Token Lifecycle — Expiration, Revocation, and Refresh

**Goal:** Test token enforcement: expired tokens rejected, revoked tokens rejected across all endpoints, refresh token behavior.

### File to create

**`tests/e2e/token_lifecycle_test.go`**

| Test                                       | Validates                                                                   |
| ------------------------------------------ | --------------------------------------------------------------------------- |
| `TestExpiredAccessToken_UserInfoRejects`   | Override expiration to 1s, wait 2s, call /oauth2/userinfo. Verify 401.      |
| `TestExpiredAccessToken_IntrospectRejects` | Same setup with /oauth2/introspect. Verify 401.                             |
| `TestRevokedToken_UserInfoRejects`         | Get tokens, revoke via /oauth2/revoke, call /oauth2/userinfo. Verify 401.   |
| `TestRevokedToken_IntrospectRejects`       | Same with /oauth2/introspect. Verify not active.                            |
| `TestRevokedToken_RefreshRejects`          | Get tokens, revoke, attempt refresh_token grant. Verify rejected.           |
| `TestRefreshToken_RotationBehavior`        | Get tokens, refresh, verify NEW access token works at /oauth2/userinfo.     |
| `TestRefreshToken_ExpiredRefresh`          | Override refresh expiration to 1s, wait, attempt refresh. Verify 401.       |
| `TestRefreshToken_InvalidRefreshToken`     | Random string as refresh_token. Verify 401.                                 |
| `TestRefreshToken_AfterLogout`             | Logout, then attempt refresh. Verify session deactivation prevents refresh. |

### File to modify

**`pkg/token/handler_test.go`** — add `TestHandleToken_RefreshTokenGrant_ExpiredRefreshToken`

---

## Phase 4: Session Management and SSO Idle Timeout

**Goal:** Test session management, SSO idle timeout auto-login, session deactivation, and logout with IdP sessions.

### File to create

**`tests/e2e/session_test.go`**

| Test                                  | Validates                                                                                                                                              |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `TestLogout_DeactivatesSession`       | Get tokens, logout, call /oauth2/userinfo with same token. Verify rejected.                                                                            |
| `TestLogout_DeactivatesIdpSession`    | With SSO enabled, login (sets IdP cookie), logout. Verify IdP cookie cleared. Visit /authorize again — login page shown (not auto-redirect).           |
| `TestLogout_MissingToken`             | POST /oauth2/logout without Authorization. Verify 401.                                                                                                 |
| `TestLogout_InvalidToken`             | POST /oauth2/logout with garbage token. Verify 401.                                                                                                    |
| `TestAutoLogin_ValidIdpSession`       | With SSO idle timeout enabled, login (creates IdP session cookie). Visit /oauth2/authorize again. Verify 302 redirect with new auth code (auto-login). |
| `TestAutoLogin_IdleTimeoutExpired`    | Manipulate idp_sessions.last_activity_at to be past timeout. Visit /authorize. Verify login page shown.                                                |
| `TestAutoLogin_DeactivatedIdpSession` | Create IdP session, deactivate in DB. Visit /authorize with cookie. Verify login page shown.                                                           |

### File to modify

**`pkg/session/logout_test.go`** — add:

- `TestHandleLogout_ClearsIdpSessionCookie`
- `TestHandleLogout_NoIdpSession`

---

## Phase 5: Client Registration and Authentication Edge Cases

**Goal:** Test client auth edge cases: confidential vs public, Basic Auth vs form-post, grant type restrictions, redirect URI enforcement.

### File to create

**`tests/e2e/client_auth_test.go`**

| Test                                   | Validates                                                                                            |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `TestConfidentialClient_BasicAuth`     | Register confidential client. Use Basic Auth at /oauth2/token. Verify token issued.                  |
| `TestConfidentialClient_FormPost`      | Same with client_id/client_secret as form params. Verify success.                                    |
| `TestConfidentialClient_MissingSecret` | Send only client_id (no secret). Verify 401 `invalid_client`.                                        |
| `TestConfidentialClient_WrongSecret`   | Wrong client_secret. Verify 401.                                                                     |
| `TestPublicClient_NoSecretRequired`    | Public client, only client_id. Verify success.                                                       |
| `TestInactiveClient_Rejected`          | Deactivate client in DB. Attempt /oauth2/authorize. Verify 400.                                      |
| `TestClient_GrantTypeRestriction`      | Client with only `["authorization_code"]`. Attempt password grant. Verify 400 `unauthorized_client`. |
| `TestClient_RedirectURIEnforcement`    | Client with specific redirect_uris. Attempt /authorize with different URI. Verify 400.               |
| `TestClient_ResponseTypeRestriction`   | Client with response_types `["token"]` only. Attempt response_type=code. Verify 400.                 |

### File to modify

**`pkg/client/authenticate_test.go`** — add:

- `TestAuthenticateClient_InactiveClient`
- `TestAuthenticateClientFromRequest_BasicAuth`
- `TestAuthenticateClientFromRequest_FormPost`
- `TestAuthenticateClientFromRequest_NoCredentials`

---

## Phase 6: Redirect URI Security and Edge Cases

**Goal:** Test redirect URI validation for security: open redirect, path traversal, fragment injection, non-HTTP schemes.

### File to modify

**`pkg/utils/redirect_uri_test.go`** — expand significantly:

| Test                                              | Validates                                                                  |
| ------------------------------------------------- | -------------------------------------------------------------------------- |
| `TestIsValidRedirectURI_NoScheme`                 | `//evil.com/callback` rejected                                             |
| `TestIsValidRedirectURI_JavascriptScheme`         | `javascript:alert(1)` rejected                                             |
| `TestIsValidRedirectURI_DataScheme`               | `data:text/html,...` rejected                                              |
| `TestIsValidRedirectURI_EmptyString`              | Empty string rejected                                                      |
| `TestIsValidRedirectURI_Fragment`                 | URI with fragment — document behavior                                      |
| `TestIsValidRedirectURI_PathTraversal`            | `http://localhost/../../../etc/passwd`                                     |
| `TestIsValidRedirectURI_PrefixMatchBypass`        | `http://allowed.com.evil.com/callback` — verify not bypassed               |
| `TestIsValidRedirectURI_PortDifference`           | Allowed `http://localhost/callback`, test `http://localhost:8080/callback` |
| `TestIsValidRedirectURI_AllowedEmpty_AnyAccepted` | When allowed list is empty, any valid URI accepted                         |

### File to create

**`tests/e2e/redirect_security_test.go`**

| Test                                     | Validates                                       |
| ---------------------------------------- | ----------------------------------------------- |
| `TestAuthorize_RejectsInvalidScheme`     | `redirect_uri=javascript:alert(1)` rejected     |
| `TestAuthorize_RejectsEmptyRedirectURI`  | No redirect_uri — rejected                      |
| `TestLogin_RejectsDisallowedRedirectURI` | POST /login with disallowed redirect — rejected |

---

## Phase 7: Userinfo and Introspect Endpoint Coverage

**Goal:** Expand thin userinfo coverage (currently 4 tests) and add missing introspect scenarios.

### File to modify

**`pkg/userinfo/handler_test.go`** — add:

| Test                                | Validates                                                                         |
| ----------------------------------- | --------------------------------------------------------------------------------- |
| `TestHandleUserInfo_ExpiredToken`   | JWT with past exp. Verify 401.                                                    |
| `TestHandleUserInfo_RevokedToken`   | Valid token, revoked in DB. Verify 401.                                           |
| `TestHandleUserInfo_UserDeleted`    | Valid token, user deleted from DB. Verify error.                                  |
| `TestHandleUserInfo_POST_Allowed`   | Document whether POST is accepted.                                                |
| `TestHandleUserInfo_ResponseFields` | Verify response contains `sub`, `email`, `username`, `scope` with correct values. |

### File to modify

**`pkg/introspect/handler_test.go`** — add:

| Test                                      | Validates                                                                      |
| ----------------------------------------- | ------------------------------------------------------------------------------ |
| `TestHandleIntrospect_ExpiredTokenInDB`   | Token in DB but expired. Verify "token has expired".                           |
| `TestHandleIntrospect_DeactivatedSession` | Session has deactivated_at set. Verify 401.                                    |
| `TestHandleIntrospect_ResponseFields`     | Verify response contains `active`, `sub`, `scope`, `token_type`, `exp`, `iat`. |
| `TestHandleIntrospect_GET_Rejected`       | GET to /introspect — document behavior.                                        |

---

## Phase 8: JWT Claim Validation and OIDC Compliance

**Goal:** Verify issued JWTs contain correct OIDC-compliant claims, JWKS endpoint produces keys that can verify tokens, audience validation works.

### File to create

**`tests/e2e/jwt_claims_test.go`**

| Test                                     | Validates                                                                              |
| ---------------------------------------- | -------------------------------------------------------------------------------------- |
| `TestAccessToken_ContainsRequiredClaims` | Decode access token, assert: `exp`, `iat`, `iss`, `aud`, `sub`, `typ`, `sid`, `scope`. |
| `TestAccessToken_IssuerMatchesConfig`    | `iss` equals `config.Get().AppAuthIssuer`.                                             |
| `TestAccessToken_AudienceMatchesConfig`  | `aud` contains all values from `config.Get().AuthAccessTokenAudience`.                 |
| `TestAccessToken_VerifiableWithJWKS`     | Fetch JWKS, use public key to verify access token signature.                           |
| `TestAccessToken_KidMatchesJWKS`         | `kid` header in JWT matches `kid` in JWKS.                                             |
| `TestAccessToken_WrongAudienceRejected`  | Override audience. Verify old token fails audience validation.                         |

### File to modify

**`pkg/jwtutil/validate_test.go`** — add:

| Test                                         | Validates                                                 |
| -------------------------------------------- | --------------------------------------------------------- |
| `TestValidateAccessToken_ExpiredToken`       | JWT with past exp. Verify error.                          |
| `TestValidateAccessToken_WrongSigningMethod` | JWT signed with HS256 instead of RS256. Verify rejection. |
| `TestValidateAccessToken_WrongAudience`      | Valid JWT, wrong audience. Verify error.                  |
| `TestValidateAccessToken_MissingExp`         | No exp claim. Verify rejection.                           |
| `TestValidateAudience_EmptyTokenAud`         | Empty token audience. Verify error.                       |
| `TestValidateAudience_SingleMatch`           | One matching audience among several. Verify success.      |

---

## Phase 9: Security Tests — Token Replay and Cross-Endpoint Abuse

**Goal:** Test security vulnerabilities: using tokens where they shouldn't work, replaying across sessions, cross-token-type abuse.

### File to create

**`tests/e2e/security_test.go`**

| Test                                         | Validates                                                               |
| -------------------------------------------- | ----------------------------------------------------------------------- |
| `TestAccessToken_CannotBeUsedAsRefreshToken` | Use access_token as refresh_token param. Verify 401.                    |
| `TestRefreshToken_CannotBeUsedAsAccessToken` | Use refresh_token in Authorization header for /userinfo. Verify 401.    |
| `TestRevokedToken_CannotIntrospect`          | Revoke, then introspect. Verify `active: false` or 401.                 |
| `TestRevokedToken_CannotGetUserInfo`         | Revoke, then userinfo. Verify 401.                                      |
| `TestDeactivatedSession_TokenRejected`       | Deactivate session in DB, use access token for userinfo. Verify 401.    |
| `TestLogout_PreventsRefresh`                 | Logout, then attempt refresh. Verify rejected.                          |
| `TestAuthCode_BoundToClient`                 | Auth code for client-A, exchange with client-B. Verify `invalid_grant`. |
| `TestAuthCode_SingleUse`                     | Exchange code, try again. Verify `invalid_grant`.                       |

---

## Phase 10: Middleware Integration Tests

**Goal:** Test middleware end-to-end: CSRF on authorize/login, CORS headers, admin auth on register.

### File to create

**`tests/e2e/middleware_test.go`**

| Test                                               | Validates                                                     |
| -------------------------------------------------- | ------------------------------------------------------------- |
| `TestCSRF_LoginWithoutToken_Rejected`              | POST /login without CSRF token. Verify 403.                   |
| `TestCSRF_LoginWithValidToken_Accepted`            | GET /authorize (get CSRF), POST /login with CSRF. Verify 302. |
| `TestCSRF_LoginWithInvalidToken_Rejected`          | POST /login with forged CSRF. Verify 403.                     |
| `TestAdminAuth_RegisterWithoutToken_Rejected`      | POST /register without auth. Verify 401.                      |
| `TestAdminAuth_RegisterWithNonAdminToken_Rejected` | Regular user token for /register. Verify 403.                 |
| `TestAdminAuth_RegisterWithAdminToken_Accepted`    | Admin token for /register. Verify 201.                        |
| `TestCORS_PreflightHeaders`                        | OPTIONS request with CORS enabled. Verify headers.            |
| `TestCORS_Disabled`                                | CORS disabled. Verify no headers.                             |

---

## Phase 11: Well-Known Discovery and Configuration Consistency

**Goal:** Verify well-known configuration is internally consistent with actual endpoints and JWKS returns usable keys.

### File to create

**`tests/e2e/discovery_test.go`**

| Test                                        | Validates                                                                                                     |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `TestWellKnownConfig_AllEndpointsReachable` | Fetch discovery doc. For each endpoint URL, make a request. Verify not 404.                                   |
| `TestWellKnownConfig_IssuerConsistency`     | Issuer matches `config.Get().AppAuthIssuer`.                                                                  |
| `TestWellKnownConfig_ScopesMatch`           | scopes_supported contains `openid`, `profile`, `email`.                                                       |
| `TestJWKS_ContainsValidKey`                 | At least one key with `kty=RSA`, `use=sig`, `alg=RS256`, non-empty `n` and `e`.                               |
| `TestJWKS_KidMatchesConfig`                 | `kid` in JWKS matches `config.Get().AuthJwkCertKeyID`.                                                        |
| `TestWellKnownConfig_DuplicatePath`         | Both `/.well-known/openid-configuration` and `/oauth2/.well-known/openid-configuration` return same response. |

---

## Implementation Sequencing

| Phase                      | Dependencies                | New Tests | Priority                     |
| -------------------------- | --------------------------- | --------- | ---------------------------- |
| 1: Test Infrastructure     | None                        | 3         | Critical (blocks all E2E)    |
| 2: Auth Code Flow Chain    | Phase 1                     | 8         | Critical (highest value gap) |
| 3: Token Lifecycle         | Phase 1                     | 10        | High                         |
| 4: Session Management      | Phase 1                     | 9         | High                         |
| 5: Client Auth Edge Cases  | Phase 1                     | 13        | Medium-High                  |
| 6: Redirect URI Security   | None (unit) + Phase 1 (E2E) | 12        | Medium-High                  |
| 7: Userinfo/Introspect     | None (unit tests)           | 9         | Medium                       |
| 8: JWT Claims / OIDC       | Phase 1                     | 13        | Medium                       |
| 9: Security Tests          | Phase 1                     | 8         | Medium-High                  |
| 10: Middleware Integration | Phase 1                     | 10        | Medium                       |
| 11: Discovery              | Phase 1                     | 6         | Low                          |

**Total new tests: ~101**

---

## Implementation Notes

1. **Test DB Isolation:** E2E tests use in-memory SQLite database (`:memory:`) for maximum performance. Database tables are cleaned between tests using `DELETE FROM` statements rather than recreating database files. This approach is faster, more resource-efficient, and eliminates file system cleanup concerns. Unit tests within `pkg/` continue using `WithTestDB(t)` and can be run in parallel with `-p` flag.

2. **CSRF in E2E Tests:** gorilla/csrf requires both a cookie (set on GET response) and a form field token. The E2E client must use a `CookieJar` so the CSRF cookie persists across GET /authorize → POST /login.

3. **Config Overrides:** Use `testutils.WithConfigOverride(t, func() { ... })`. For E2E tests, also set `config.Values.AppURL`, `config.Values.AppHost`, and `config.Values.AppAuthIssuer` to match the test server's dynamically assigned port.

4. **Key Loading:** Test server setup must ensure RSA keys are loaded before starting. `key.GetPrivateKey()` loads from `config.Get().AuthPrivateKeyFile` (default `./db/private_key.pem`). E2E setup must ensure the path resolves correctly.

5. **Sequential Execution:** All tests use `go test -p 1`. The E2E package (`tests/e2e`) runs sequentially. Each test creates its own server and DB for isolation.

6. **PKCE and Nonce:** The authorize handler parses `code_challenge` and `nonce` but does not use them (TODO). PKCE tests should be added once the implementation exists.
