# Security Code Review: claude-opus-5-5

| Field | Value |
|---|---|
| Date | 2026-10-20 |
| Auditor | claude-opus-5-5 (Claude Code), static review with 6 parallel agents plus handler-level PoC tests; HIGH findings re-verified manually. Run by eugenioenko. |
| Commit audited | 3f1efdd |
| Scope | 6 dimensions: (1) PRs #452, #453, #455, #457, #458; (2) token endpoint, all grants, device code, client auth, registration, introspect/revoke; (3) federation, signup, email verification, magic link, onboarding, password reset; (4) browser auth state machine: authorize, login, MFA, consent, passkey, trusted device, SSO, logout; (5) admin/account API authorization and custom claims; (6) web layer: CSRF, CORS, rate limiting, CSP, templates, email, frontends, logging, secrets |

Known open issues were excluded from re-reporting: #444 (TOTP secrets at rest; de-prioritized), #447, #450, #456, #358, #459.

PoC tests were written in throwaway copies outside the repo; no code was changed. Confidence key: **test** = reproduced with a handler-level test, **read** = confirmed by reading the code paths end to end.

## Findings

| Severity | Finding | Location | Confidence | Status |
|---|---|---|---|---|
| HIGH | Federation begin signs unvalidated `client_id`/`redirect_uri`/`scope` into state; callback issues a code to that URI. Codes with empty `client_id` skip client binding at the token endpoint, so a crafted link can steal a victim's code and tokens. | `pkg/federation/handler.go:72-83,286-315`, `pkg/token/authorization_code.go:47` | test | Open ([#462](https://github.com/eugenioenko/autentico/issues/462)) |
| HIGH | Magic-link GET is an `authzsig` signing oracle (signs raw query params). Verify-email trusts the signature without client/redirect validation, so a genuine verification email can deliver a code to an attacker URI. Passkey and signup also trust the signature without re-validation. | `pkg/magiclink/handler.go:109-120`, `pkg/emailverification/handler.go:120-255`, `pkg/passkey/handler.go:50,196,493,651`, `pkg/signup/handler.go:86` | test | Open ([#463](https://github.com/eugenioenko/autentico/issues/463)) |
| HIGH | Client IP is the leftmost `X-Forwarded-For`; per-IP rate limiting bypassed by rotating the header (30 attempts never throttled vs 429 after ~12). No trusted-proxy setting. Also forges audit/session IPs. | `pkg/utils/get_client_ip.go:10-14`, `pkg/middleware/rate_limit.go:18` | test | Open ([#464](https://github.com/eugenioenko/autentico/issues/464)) |
| HIGH | Passkey registration ignores `allow_self_signup`, `auth_mode` and `require_email_verification`; routes not rate-limited; stale in-progress usernames can be re-claimed. Found independently by 3 agents. | `pkg/passkey/handler.go:36-104,382`, `pkg/cli/start.go:153-154` | test | Open ([#465](https://github.com/eugenioenko/autentico/issues/465)) |
| MEDIUM | Refresh grant without `client_id` skips client authentication, grant allowlist, active check and client binding; new tokens get `azp=""`. | `pkg/client/authenticate.go:77-78`, `pkg/token/handler.go:95`, `pkg/token/refresh_token.go:51` | test | Open ([#466](https://github.com/eugenioenko/autentico/issues/466)) |
| MEDIUM | Read-check-update races: auth codes (3-7 of 20 parallel redemptions succeed), refresh rotation (forked families survive replay detection), device codes (error ignored). Code-replay revocation misses refreshed tokens. | `pkg/auth_code/update.go:8-14`, `pkg/token/handler.go:300-307`, `pkg/devicecode/update.go:25-30`, `pkg/token/device_code.go:75`, `pkg/token/revoke.go:15-19` | test | Open ([#467](https://github.com/eugenioenko/autentico/issues/467)) |
| MEDIUM | Federation, passkey, verify-email and signup code paths skip `require_mfa`, enrolled TOTP and/or `consent_required`. | `pkg/federation/handler.go:286`, `pkg/passkey/handler.go:651`, `pkg/emailverification/handler.go:120-192`, `pkg/signup/handler.go` | read | Open ([#468](https://github.com/eugenioenko/autentico/issues/468)) |
| MEDIUM | #457's account-level TOTP lockout only covers the password grant; browser MFA allows 5 guesses per challenge with unlimited challenges; TOTP removal has no limit. | `pkg/mfa/handler.go:191-201`, `pkg/account/mfa.go:185` | read | Open ([#469](https://github.com/eugenioenko/autentico/issues/469)) |
| MEDIUM | Magic-link code budget resets with each new link request; no per-user cooldown. | `pkg/magiclink/handler.go:156-185` | read | Open ([#470](https://github.com/eugenioenko/autentico/issues/470)) |
| MEDIUM | Consent GET signs arbitrary params; POST skips scope allowlist, PKCE for public clients, `consent_required`, SSO idle timeout/max age; `auth_time` set to now. | `pkg/consent/handler.go:45-160`, `pkg/auth_code/create.go:10` | test | Open ([#471](https://github.com/eugenioenko/autentico/issues/471)) |
| MEDIUM | Per-client overrides `allow_self_signup`, `sso_session_idle_timeout`, `trust_device_enabled`, `trust_device_expiration` ignored in browser flows (`GetForClient` only used in `pkg/token`). | `pkg/signup/handler.go:39`, `pkg/authorize/handler.go:134,169,210,305`, `pkg/login/handler.go:141,157`, `pkg/mfa/handler.go:160,227` | test | Open ([#472](https://github.com/eugenioenko/autentico/issues/472)) |
| MEDIUM | Federation upstream `state` not bound to the browser, no expiry, not single-use: login CSRF into an attacker's account with SSO spread. | `pkg/federation/service.go` | read | Fixed ([#473](https://github.com/eugenioenko/autentico/issues/473)) |
| LOW | Introspection bearer fallback checks admin role but not admin audience or `azp`; public clients authenticate with `client_id` only. | `pkg/introspect/handler.go:62-73,126`, `pkg/client/authenticate.go:62-66` | read | Open ([#474](https://github.com/eugenioenko/autentico/issues/474)) |
| LOW | Federation SSRF guard only checks redirects, not the initial dial or discovery-derived endpoints; DNS rebinding possible. SSRF test posts to a non-existent route and passes vacuously. | `pkg/federation/safeclient.go:58-63`, `tests/security/security_ssrf_test.go:42` | test | Open ([#475](https://github.com/eugenioenko/autentico/issues/475)) |
| LOW | `*` in redirect URIs is an unanchored glob matching dot-segments and `?`; README says wildcards are unsupported. | `pkg/client/authenticate.go:92-97`, `README.md:789` | test | Open ([#476](https://github.com/eugenioenko/autentico/issues/476)) |
| LOW | `state` interpolated unencoded into redirect URLs (parameter injection, breaks URIs with existing query). | `pkg/mfa/handler.go:299`, `pkg/passkey/handler.go:685`, `pkg/federation/handler.go:313`, `pkg/emailverification/handler.go:191`, `pkg/session/logout.go:194` | read | Open ([#477](https://github.com/eugenioenko/autentico/issues/477)) |
| LOW | Resend-verification returns "already verified" for existing users; synchronous send leaks timing. | `pkg/emailverification/handler.go:227` | read | Open ([#478](https://github.com/eugenioenko/autentico/issues/478)) |
| LOW | Request logger writes full query strings, including reset and magic-link tokens. | `pkg/middleware/logging.go:64-69` | read | Open ([#479](https://github.com/eugenioenko/autentico/issues/479)) |
| LOW | Self-service deletion hard-deletes on a bearer token alone, with no audit event. | `pkg/deletion/handler.go:41-48` | read | Open ([#480](https://github.com/eugenioenko/autentico/issues/480)) |
| LOW | Last admin can be demoted, deactivated or deleted; `onboard` refuses once users exist, so no recovery path. | `pkg/user/handler.go:98-210`, `pkg/cli/onboard.go:61-66` | read | Open ([#481](https://github.com/eugenioenko/autentico/issues/481)) |
| LOW | Session rows expire with the access token; cleanup deletes them, breaking refresh after idle and disabling replay detection for rotated tokens. | `pkg/token/handler.go:383`, `pkg/cleanup/service.go:31`, `pkg/token/refresh_token.go:43` | read | Open ([#482](https://github.com/eugenioenko/autentico/issues/482)) |

## What passed

- **#458 token hashing:** every `tokens`/`sessions` lookup uses `utils.HashToken` (bearer validation, admin/account middleware, userinfo, introspect, revoke, cascade, refresh). No digests in API responses, no raw tokens in logs or audit entries. `HashToken("")` is rejected by readers. Schema 15 migration wipes tokens, sessions, IdP sessions and pending grants with `secure_delete` and a WAL checkpoint.
- **#452 migrations:** SQL and version stamp applied in one transaction; failed COMMIT rolled back on the reserved connection.
- **#453/#455 magic link:** guarded `failed_attempts < 5` UPDATE cannot be raced past the limit; URL and code redemption share one guarded claim; expiry checked in the transaction. Magic-link login itself re-validates client, redirect, scopes, MFA and consent.
- **#457 password-grant TOTP:** read/check/update in one writer transaction; admin unlock clears both counters.
- **Token endpoint:** codes bound to `client_id` and `redirect_uri` when a client is present; PKCE format/method enforced, no S256-to-plain downgrade; refresh downscoping is a subset check; refresh requires `acr` 2 for TOTP users; deactivated sessions/users rejected; `client_credentials` confidential-only, `openid` stripped, no refresh token; ID tokens and HS256 refresh tokens unusable as access tokens.
- **Device flow:** `user_code` CSPRNG (~34.6 bits) behind account auth and rate limiting; `device_code` 160 bits; approval only for pending codes; JSON + bearer endpoints, no CSRF exposure.
- **Clients:** bcrypt secrets; `/oauth2/register` is admin-only.
- **Admin API:** every `/admin/api/*` and `/oauth2/register*` route behind `adminAPI`. `AdminAuthMiddleware`: RS256 only, `aud` contains `autentico-admin`, role from DB, deactivated users excluded, active session and unrevoked token required. #358's mitigation holds.
- **Account API:** all routes behind `AccountAuthMiddleware` except public `GET /account/api/settings`. Session, passkey, trusted device, federated identity and passkey challenge operations are owner-checked. Password change needs current password; TOTP disable needs password and TOTP; email/username change needs password and resets `email_verified`; profile update cannot set `role`.
- **Custom claims (#398):** reserved names (case-insensitive) cover `sub`, `iss`, `aud`, `exp`, `role`, `email_verified`, `azp`, `groups`, `scope`, `typ` and more; builders never overwrite set claims; introspection does not emit custom claims.
- **Settings:** `private_key` and `onboarded` protected; `smtp_password` and `private_key` stripped from GET; import skips unknown keys; `logout_success_url`, `theme_logo_url`, client `logo_uri`/`client_uri` validated.
- **Federation:** auto-linking requires upstream `email_verified` and a verified local email (no pre-hijack); upstream ID tokens verified by go-oidc (signature, `iss`, `aud`, `exp`); userinfo not trusted; #414 name copying only on creation and cannot touch email, username or role; deactivated users blocked; icons served as SVG with a sandbox CSP.
- **Browser flows:** trusted-device cookie bound to user and expiry (Strict, HttpOnly); MFA challenge state server-side; login re-validates client/redirect/scope; consent superset logic correct; `prompt=login` and `max_age` honored at authorize; fresh IdP session ID per login (no fixation); `post_logout_redirect_uri` exact-match; `client_id`/`id_token_hint` mismatch rejected; authorize renders an error page for invalid redirect URIs.
- **Web layer:** CORS never reflects unlisted origins or combines credentials with `*`; gorilla/csrf on all interactive POSTs with no exemptions; security headers and per-request CSP nonces; #424 logo URL validated and scoped in `img-src`; #425 signed-out link escaped by `html/template`; `theme.css` served as `text/css`; email headers safe (`mail.ParseAddress`, `mime.QEncoding`, #420); frontends use `oidc-js-react`, no `dangerouslySetInnerHTML`/`innerHTML`/`eval`; `.env` written `0600`; RSA-2048 via `crypto/rand`.
- **Onboarding:** locked once any user exists (narrow race on a fresh DB only). Forgot-password responds identically and sends asynchronously.

## False positives

| Claim | Evidence against |
|---|---|
| Revocation ownership by `azp` lets a client revoke another client's token by editing claims | The token row is looked up by the hash of the full presented string, and the JWT signature is verified first; edited claims cannot match a different row. |
| Newline ambiguity in the `authzsig` canonical string enables parameter smuggling | Investigated in the browser-flow dimension; no exploitable collision found. Not filed. |
| `switch_to=email` lets an attacker downgrade from TOTP to email OTP | Documented behavior when `mfa_method=both`; the attacker still needs the user's email inbox. Accepted design, not filed. |
| Missing `iss` check in bearer validation | Only this server's RSA key is accepted, so no foreign issuer can produce a valid signature. |

## See also

- Prior coverage: [2026-06-10 claude-fable-5 review](2026-06-10-claude-fable-5-security-review.md), [2026-04-08 sectool audit](2026-04-08-sectool-claude-audit.md), [2026-04-03 ZAP scan](2026-04-03-owasp-zap-scan.md)
- CVE-mapped regression tests: `tests/security/CVE_REFERENCE.md`
