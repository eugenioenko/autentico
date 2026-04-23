# CVE Reference — Negative-Path Security Tests

Portable OAuth2/OIDC CVEs from Keycloak, Auth0, and Okta mapped to test files in this directory.
Only protocol-level issues that translate to any compliant IdP are included; implementation-specific
bugs (Java deserialization, SAML adapters, admin console XSS) are excluded.

Sources:
- [OpenCVE — Keycloak](https://app.opencve.io/cve/?product=keycloak&vendor=redhat)
- [OpenCVE — Authentik](https://app.opencve.io/cve/?product=authentik&vendor=goauthentik)
- [OpenCVE — ORY (Hydra/Fosite)](https://app.opencve.io/cve/?vendor=ory)
- [OpenCVE — mod_auth_openidc](https://app.opencve.io/cve/?product=mod_auth_openidc&vendor=openidc)
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/rfc9700/)
- [RFC 6819 — OAuth 2.0 Threat Model](https://datatracker.ietf.org/doc/rfc6819/)

---

## 1. Redirect URI Validation (`security_redirect_uri_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2023-6291 | 7.1 | Keycloak: Loose string comparison — prefix match instead of exact | `https://allowed.com.evil.com/callback` |
| CVE-2023-6927 | 4.6 | Keycloak: Wildcard URI bypass via JARM `form_post.jwt` | `http://localhost/callback/../evil` |
| CVE-2024-1132 | 8.1 | Keycloak: Wildcard redirect URI traversal | `http://localhost/callback/..%2F..%2Fevil` |
| CVE-2024-8883 | — | Keycloak: Localhost/127.0.0.1 open redirect | `http://localhost@evil.com/callback` |
| CVE-2022-3782 | 9.1 | Keycloak: Double URL encoding path traversal | `http://localhost/callback%252f..%252f` |
| CVE-2026-3872 | — | Keycloak: `..;/` path traversal in OIDC auth endpoint | `http://localhost/callback/..;/evil` |
| CVE-2024-52289 | 9.8 | Authentik: Regex bypass — unescaped dot in domain (`fooaexample.com` matches `foo.example.com`) | `https://fooaexample.com/callback` |
| CVE-2020-15234 | 6.1 | Fosite: Redirect URL case-sensitivity bypass | `HTTP://LOCALHOST/Callback` (case variants) |
| CVE-2020-15233 | 6.1 | Fosite: Loopback adapter redirect URI override | `http://127.0.0.1/callback` with port override |
| CVE-2022-23527 | 4.7 | mod_auth_openidc: Open redirect with `/\t` prefix bypass | `/\thttps://evil.com` |
| CVE-2019-20479 | 6.1 | mod_auth_openidc: Open redirect via slash/backslash prefix | `\/evil.com` |
| CVE-2019-14857 | 6.1 | mod_auth_openidc: Open redirect via trailing slashes | `https://allowed.com///evil.com` |
| CVE-2018-14658 | — | Keycloak: Open redirect through improper redirect URL normalization | URL normalization bypass |
| RFC 9700 §4.1.3 | — | Fragment in redirect URI must be rejected | `http://localhost/callback#fragment` |
| RFC 9700 §4.1.3 | — | Exact string matching required | various |

## 2. Authorization Code Reuse (`security_auth_code_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2026-4282 | — | Single-use code bypass / forged authorization codes | Replay same code twice |
| RFC 6749 §4.1.2 | — | Code MUST be single-use; second use SHOULD revoke tokens | Exchange, then re-exchange |
| RFC 6749 §10.5 | — | Code must be bound to client_id | Exchange with different client |

## 3. PKCE Downgrade (`security_pkce_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2024-23647 | 6.5 | Authentik: PKCE downgrade — removing `code_challenge` bypasses PKCE | Omit `code_challenge` from authorize request |
| RFC 9700 §2.1.1 | — | code_verifier must be required if code_challenge was sent | Omit verifier at token exchange |
| RFC 7636 §4.6 | — | Wrong verifier must fail | Send incorrect verifier |
| — | — | Mismatched code_challenge_method | Send `plain` challenge, verify with `S256` |

## 4. JWT Algorithm Confusion (`security_jwt_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2022-23539 | — | Auth0: `alg=none` accepted | Craft JWT with `alg: "none"`, empty signature |
| CVE-2022-23540 | — | Auth0: RS256→HS256 confusion | Craft JWT signed with public key as HMAC secret |
| CVE-2022-23541 | — | Auth0: missing algorithm enforcement | Craft JWT with unexpected algorithm |
| CVE-2026-23552 | — | Missing issuer claim validation | Craft JWT with wrong `iss` |
| CVE-2020-5300 | 5.8 | Hydra: JWT `jti` claim uniqueness not validated (replay) | Reuse a JWT with same `jti` |
| CVE-2020-15222 | 8.1 | Fosite: JWT `jti` reuse in `private_key_jwt` client auth | Replay `client_assertion` JWT |
| RFC 9700 §3.2 | — | Token must validate `aud` claim | Craft JWT with wrong `aud` |

## 5. Refresh Token Abuse (`security_refresh_token_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2026-1035 | — | Keycloak: Refresh token reuse bypass (TOCTOU race) | Use same refresh token twice |
| CVE-2022-3916 | 6.8 | Keycloak: Offline session / refresh token reuse | Use revoked refresh token |
| CVE-2020-15223 | 8.0 | Fosite: Token revocation handler error leaks info | Revoke with malformed token, check response |
| CVE-2024-52287 | 7.2 | Authentik: Scope escalation in device_code/client_credentials | Request broader scope than configured |
| RFC 6749 §10.4 | — | Refresh token rotation — old token must be invalidated | Refresh, then reuse old token |
| — | — | Scope elevation via refresh | Request broader scope on refresh |

## 6. Session Security (`security_session_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2023-6787 | 6.5 | `prompt=login` re-auth cancel → session hijack | Cancel re-auth, check session state |
| CVE-2017-12159 | — | CSRF token fixation | Verify CSRF token changes per session |
| CVE-2020-10734 | — | OIDC logout endpoint CSRF | GET to logout endpoint without token |
| CVE-2024-7341 | 7.1 | Session fixation — session ID not rotated at login | Check session ID before/after auth |
| RFC 9700 §4.13 | — | `prompt=none` without session must fail | `prompt=none` with no IdP session cookie |

## 7. SSRF in Federation (`security_ssrf_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2020-10770 | 5.3 | SSRF via `request_uri` OIDC parameter | `request_uri=http://169.254.169.254/...` |
| CVE-2026-1180 | — | SSRF via `jwks_uri` in dynamic client registration | Internal URL in `jwks_uri` field |
| — | — | Federation provider with internal issuer URL | `issuer=http://127.0.0.1/...` |

## 8. Token Validation (`security_token_validation_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2020-14389 | 8.1 | Keycloak: Token audience verification bypass | Token with mismatched audience |
| CVE-2017-12160 | 7.2 | Keycloak: Token usable after permission revocation | Deactivate session, try to use token |
| CVE-2020-14302 | 4.9 | Keycloak: State parameter replay on federation callback | Reuse state across requests |
| CVE-2021-32701 | 7.5 | Hydra: Introspection cache ignores scope requirements | Introspect token with mismatched scope |
| CVE-2025-64521 | 4.8 | Authentik: Deactivated service account still authenticates via client_id/secret | Deactivate user, attempt ROPC/login |
| CVE-2024-38371 | 8.6 | Authentik: Authorization bypass in device code flow | Device code grant ignoring access restrictions |

## 9. MFA Brute Force (`security_mfa_test.go`)

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2018-14657 | 8.1 | Keycloak: TOTP brute force — no rate limiting on OTP attempts | Rapid sequential OTP guesses |
| CVE-2020-10686 | 4.1 | Keycloak: Unauthorized MFA device removal | Remove MFA device without proper auth |

## 10. Authentication Header / Claim Injection

| CVE | CVSS | Summary | Test vector |
|-----|------|---------|-------------|
| CVE-2017-6413 | — | mod_auth_openidc: Auth bypass via unfiltered OIDC_CLAIM headers | Inject `OIDC_CLAIM_*` headers in request |
| CVE-2017-6062 | — | mod_auth_openidc: Auth bypass via unfiltered headers in pass mode | Inject auth headers to bypass validation |

## Not Yet Covered (Future Work)

- IDN / Unicode homograph in usernames/emails (ties to #223, #224)
- Timing side-channels on credential validation (`RandomDelay` coverage)
- Dynamic client registration abuse beyond SSRF
- OIDC conformance suite negative test plans
- Token introspection with revoked/expired tokens
- XSS via `response_mode=form_post` with JavaScript URIs (Authentik CVE-2024-21637)
- SAML signature bypass via XML encoding (Dex CVE-2020-26290, if SAML is added)
- Protocol confusion via `X-Forwarded-Proto` header (ORY CVE-2026-33495)
- Static IV in AES-GCM encryption (mod_auth_openidc CVE-2021-32791, if applicable)
