# OpenID Connect Conformance — Issues Found

Issues discovered while running the [OpenID Connect Core Basic OP certification test plan](https://openid.net/certification/) against Autentico. Listed in the order they were found.

## 1. ID token includes non-requested claims (oidcc-server)

**Commit:** `7c5ca98`

**Problem:** The ID token included `name`, `preferred_username`, `email`, and `email_verified` whenever `openid` scope was present — which is always. The conformance suite only requested `openid` scope and did not expect these claims.

**Fix:** Profile claims (`name`, `preferred_username`) are now only included in the ID token when `profile` scope is explicitly requested. Email claims (`email`, `email_verified`) are only included when `email` scope is explicitly requested.

---

## 2. Authorization errors returned as JSON instead of redirect (oidcc-response-type-missing)

**Commit:** `ab1cc4b`

**Problem:** When `response_type` was missing or invalid, Autentico returned a JSON error directly. Per the OIDC/OAuth2 spec, when `redirect_uri` and `client_id` are valid the server must redirect back to the client with error params (`?error=invalid_request&...`).

**Fix:** Validation order was changed to check `redirect_uri` and `client_id` first. All subsequent errors (missing/unsupported `response_type`, invalid scope, plain PKCE rejected) now redirect back to the client. Unrecoverable errors (invalid `redirect_uri`, unknown `client_id`) still show an HTML error page since redirecting would be unsafe.

Additionally, `response_type` validation was relaxed to accept any non-empty value so unsupported types return `error=unsupported_response_type` via redirect rather than `error=invalid_request`.

---

## 3. Userinfo endpoint did not support access_token in POST body (oidcc-userinfo-post-body)

**Commit:** `726414a`

**Problem:** The `/oauth2/userinfo` endpoint only accepted the access token via the `Authorization: Bearer` header. Per RFC 6750 §2.2, POST requests with `Content-Type: application/x-www-form-urlencoded` should also be able to pass the token as an `access_token` form parameter.

**Fix:** The handler now checks for the token in the POST body when no `Authorization` header is present.

---

## 4. Userinfo endpoint did not gate claims by scope (oidcc-scope-profile)

**Commit:** `623f039`

**Problem:** The userinfo endpoint always returned `preferred_username` and `email` regardless of the requested scope. When only `openid profile` was requested (no `email` scope), the conformance suite warned that claims not corresponding to the requested scopes were present.

**Fix:** Userinfo claims are now gated by scope:
- `profile` scope → `name`, `preferred_username`, `given_name`, `family_name`, `picture`, `locale`, `zoneinfo`
- `email` scope → `email`, `email_verified`
- `phone` scope → `phone_number`
- `address` scope → `address`
- `name` falls back to `username` when `given_name`/`family_name` are not set

---

## 5. Userinfo missing standard profile claims when profile scope requested (oidcc-scope-profile)

**Commit:** TBD

**Problem:** The conformance suite warned that the userinfo response was missing standard OIDC profile claims when `profile` scope was requested. Per OIDC Core §5.4, all standard profile claims (`given_name`, `family_name`, `middle_name`, `nickname`, `website`, `gender`, `birthdate`, `profile`, `picture`, `locale`, `zoneinfo`, `updated_at`) must be present in the response — even if null.

Additionally, several claims (`middle_name`, `nickname`, `website`, `gender`, `birthdate`, `profile`) did not exist as fields in the User model or database at all.

**Fix:**
- Added `middle_name`, `nickname`, `website`, `gender`, `birthdate`, `profile` columns to the `users` table.
- Added corresponding fields to the `User` struct, `UserResponse`, `UserUpdateRequest`, and `ToResponse()`.
- Updated `userSelectColumns` and `scanUser` to include `updated_at` and all new fields.
- Updated `HandleUserInfo` to always emit all standard profile claims when `profile` scope is present, using `null` for empty values instead of omitting them entirely.

---

## 6. Email claims in id_token caused failures for oidcc-scope-email (oidcc-scope-email)

**Commit:** TBD

**Problem:** Two failures:
1. The admin test user had no email address set, causing `email is not a string with content` failures in both id_token and userinfo validation.
2. The id_token included `email` and `email_verified` when `email` scope was present. The conformance suite warned this is unexpected — per OIDC Core §5.4, `scope=email` is shorthand for granting access to the user's email via the userinfo endpoint, not a request to include it in the id_token.

**Fix:**
- Removed `email` and `email_verified` from the id_token entirely. Email claims are now only served via the userinfo endpoint.
- Updated `generate_test.go` to assert email is never present in the id_token regardless of scope.

---

## 7. address and phone scopes not advertised or enforced (oidcc-scope-address)

**Commit:** TBD

**Problem:** Two issues:
1. The `/.well-known/openid-configuration` did not advertise `address`, `phone`, or `offline_access` in `scopes_supported`, causing the conformance suite to skip the test entirely.
2. Even after advertising the scopes, the `address` claim was only included in the userinfo response when at least one address field was non-empty, causing a missing claim warning.

**Fix:**
- Added `address`, `phone`, and `offline_access` to `scopes_supported` and expanded `claims_supported` in the well-known handler.
- Updated all OAuth2 clients to allow the new scopes.
- `address` is now always present in the userinfo response when `address` scope is requested: a populated address object if any field has content, or `null` if the user has no address data.
- Same applied to `phone_number` — always emitted (as `null` if empty) when `phone` scope is requested.

---

## 8. phone_number_verified missing from userinfo phone scope response (oidcc-scope-phone)

**Commit:** TBD

**Problem:** When `phone` scope was requested, the userinfo response included `phone_number` but was missing `phone_number_verified`. Per OIDC Core §5.1, both claims are part of the `phone` scope.

**Fix:**
- Added `phone_number_verified` column to the `users` table and field to the `User` model.
- Updated `HandleUserInfo` to always emit both `phone_number` and `phone_number_verified` when `phone` scope is present.

---

## 9. prompt=login bypassed by SSO auto-login; prompt=none failed due to SameSite=Strict cookie (oidcc-prompt-login, oidcc-prompt-none-logged-in)

**Commits:** TBD

**Problem:** Two related issues:

1. `prompt=login`: The SSO auto-login check ran before the `prompt=login` check. When a valid IdP session existed, the server auto-logged in without prompting the user to re-authenticate, violating OIDC Core §3.1.2.1.

2. `prompt=none`: The IdP session cookie was set with `SameSite=Strict`. OIDC flows involve cross-site redirects by design (e.g. `client.example.com` → `idp.example.com/oauth2/authorize`). With Strict, the browser blocks the cookie on these top-level cross-site navigations, so the server never saw the session and returned `login_required`.

3. `auth_time` inconsistency: When SSO auto-login issued a new auth code, `auth_time` in the resulting ID token was set to `time.Now()` instead of the original authentication time. Per OIDC Core §2, `auth_time` must reflect when the user actually authenticated, not when the token was issued.

**Fix:**
- `prompt=login`: Added `&& request.Prompt != "login"` guard to the SSO auto-login block so it is skipped when `prompt=login` is present.
- `SameSite=Strict` → `SameSite=Lax`: Lax allows the cookie to be sent on top-level GET navigations (which is exactly what OIDC authorize redirects are) while still blocking it on subrequests. This is the correct setting for all IdP session cookies and matches Auth0, Okta, and Keycloak's behaviour.
- `auth_time`: `GenerateIDToken` now accepts an explicit `authTime time.Time` parameter. For SSO auto-login the auth code `CreatedAt` is set to `session.CreatedAt`, so the original authentication time is preserved through to the ID token.

---

## 10. max_age not enforced — SSO auto-login ignored max_age parameter (oidcc-max-age-1)

**Commit:** TBD

**Problem:** When `max_age` was sent on the second authorization request, the SSO auto-login check did not compare the session age against `max_age`. The server used the existing IdP session and returned the original `auth_time`, so the conformance suite saw `auth_time` identical to the first run and failed `CheckSecondIdTokenAuthTimeIsLaterIfPresent` and `CheckIdTokenAuthTimeIsRecentIfPresent`.

**Fix:**
- Added `MaxAge string` field to `AuthorizeRequest`.
- Added `parseMaxAge(s string) int64` helper: parses the value as seconds, returns `-1` if absent or invalid.
- In the SSO auto-login block: compute `sessionAge := time.Since(session.CreatedAt)` and set `maxAgeExceeded := maxAgeSecs >= 0 && sessionAge > time.Duration(maxAgeSecs)*time.Second`. SSO auto-login is skipped when `maxAgeExceeded` is true, forcing the user to re-authenticate and producing a fresh `auth_time`.

---

## Setup Notes

- Conformance suite runs via Docker at `https://localhost:8443` (source: `/tmp/conformance-suite`, docker-compose)
- Autentico must run with `AUTENTICO_APP_URL=http://172.17.0.1:9999` so Docker containers can reach it
- Use `make conformance-server` to start Autentico with the right flags
- Saved test plan config: see memory file `reference_conformance_suite.md`
