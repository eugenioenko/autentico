# Security and Behavior Invariants

Design notes for security-sensitive behavior, moved out of `AGENTS.md` so agent context stays small. Each section records the rules a change in that area must preserve. Issue/PR numbers point to the full discussion. Schema numbers mentioned below are historical: the migration that introduced the change, not the current version.

When you change one of these areas, update its section in the same PR. When you add a security-sensitive feature, add a section here instead of to `AGENTS.md`.

## Passkey signup policy

Public passkey registration checks current self-signup policy (including client overrides) and passkey auth mode at begin and finish. A five-minute HttpOnly cookie binds pending registration to its browser. Required email verification gates registration and both passkey login modes before session/code issuance. The internal `/oauth2/verify-email/pending` page resumes the existing resend flow without exposing the email token. Registration routes share the authentication rate limiter. Named and discoverable login recheck that the auth mode allows passkeys at begin, finish, and final session/code issuance.

## Trusted proxy client IPs

`AUTENTICO_TRUSTED_PROXIES` is a bootstrap list of IPv4/IPv6 CIDRs, empty by default. `InitBootstrap` returns an error for invalid entries; CLI callers must propagate it. `utils.GetClientIP` uses the network peer unless trusted, then walks all `X-Forwarded-For` fields from right to left until the first untrusted hop. Rate limits, audit logs and session records use this same resolver. Forwarding values before that boundary, `X-Real-IP`, and `Forwarded` do not establish identity.

## TOTP encryption and schema 17

`pkg/totpsecret` uses AES-256-GCM with a fresh nonce and authenticated user ID/version. `AUTENTICO_TOTP_ENCRYPTION_KEY` is a required persistent base64-encoded 32-byte bootstrap key. Fresh `init`/auto-setup include it; re-running `init` on an existing regular `.env` only adds a missing key and preserves existing settings and secrets. Startup and migration reject missing/invalid keys; startup and up-to-date migration validate stored enrollments against the key. There is no plaintext or ephemeral-key fallback.

Schema 17 is a major offline transformation with backup/recovery and explicit approval. It encrypts all nonempty active, pending and deactivated TOTP seeds in place, preserving enrollment flags, replay state and lockout. It does not discard sessions. Schema 15 still discards access and refresh tokens, OAuth/SSO sessions and pending login grants. Pre-v3 unattended upgrades approve `15,17`; schema 15/16 upgrades approve `17`. Keep the original encryption key for all restarts and database restores.

## Refresh client binding

Refresh requests require a registered client, using the shared authentication and active/grant checks. Confidential clients supply their secret; public clients identify themselves with `client_id`. The refresh JWT, stored token and session must agree on client/user binding. Historical tokens with no client binding are rejected rather than reassigned; no migration is required.

## Atomic token issuance

`token.storeGrantTokens` claims authorization codes, approved device codes or refresh tokens through a conditional update and inserts the replacement token/session pair in one writer transaction. A failed insert or commit rolls back consumption; no refresh cookie or successful response precedes commit. Expiry is checked again inside the transaction. Code-replay revocation follows the existing browser IdP-session linkage through refresh rotation; codes without linkage conservatively revoke code/refresh grants for that user/client. Refresh replay keeps the existing account-wide revocation policy. No schema migration is required.

## Atomic password resets and MFA challenges

`passwordreset.resetPassword` hashes outside the writer lock, then conditionally consumes one unused reset token, updates the active user's password, and deactivates OAuth/IdP sessions in one transaction. Expiry is rechecked after obtaining the writer. Failed writes or commits leave the token, password and sessions unchanged; success and its audit event follow commit.

`mfa.ConsumeMfaChallenge` conditionally consumes the verified snapshot (user, method, code and login state), rejecting reused, exhausted, changed or expired challenges. The browser handler must commit consumption before success audit, trusted-device cookies, authenticated sessions, consent or authorization-code issuance. Both paths explicitly clean up SQLite transactions after failed commits. No schema migration is required.

## Introspection token lifetimes

`introspect.tokenExpiration` selects access or refresh expiry from the hash that matched the stored pair. Both `IntrospectToken` and the response's `exp` use this helper; expiry at the current second is inactive, matching signed JWT `exp` precision. The shared token record keeps its original access and refresh timestamps for UserInfo and session lookup.

## Callback query encoding

Password login, SSO, consent approval/denial, authorization errors, browser MFA and RP-initiated logout parse registered callback URLs and add response values with `url.Values.Set`/`Encode`, preserving existing query values and round-tripping opaque state. MFA parses the restored callback before issuing authenticated state. Malformed registered logout URLs render the signed-out page without redirection. Passkey, federation and email-verification callbacks already use encoded query construction.

## Verification resend privacy

`emailverification.HandleResendVerification` keeps authorization signature/client/redirect/scope/PKCE validation before account lookup. Accepted requests use one randomized-delay policy and one deferred generic sent-page response for unknown, inactive, verified, email-less or eligible accounts, including token-storage errors. Eight delivery slots per process bound detached work; nonblocking admission happens before replacing a token, and missing SMTP configuration also preserves the existing link. Admitted tokens are stored before asynchronous email dispatch. Missing SMTP configuration, capacity exhaustion and delivery failures are logged privately; the background sender captures only recipient, URL and request ID. The private handler takes a sender function for deterministic blocked-delivery tests.

SMTP transport uses `net/smtp.Client` with a 30-second connect timeout and a fresh 30-second deadline for each greeting/command/data operation. STARTTLS uses normal certificate/host verification; configured authentication requires advertised AUTH. All exits close the connection, including greeting and TLS failures.

## Redirect wildcard compatibility

Exact redirect registrations compare byte-for-byte. The explicit conformance-callback extension permits one `*` as an entire path segment, matching a nonempty plain unreserved identifier (`A-Z a-z 0-9 - . _ ~`) other than `.` or `..`. `redirectWildcardParts` validates pattern shape and rejects traversal/fragments; `matchesRedirectWildcard` retains literal prefix/suffix bytes and never decodes the candidate. Variable separators, percent escaping, queries, fragments, backslashes and controls cannot match. Invalid patterns fail at registration/update and at runtime for older stored rows. Conformance `/test/a/*/callback` still works; root `/*` no longer matches multiple path segments.

## OAuth session cleanup lifetimes

New token grants set session expiry to the later access/refresh expiry. `cleanup.cleanTokenSessions` uses a writer transaction to extend older session metadata from the matching stored user/access/refresh binding and purge only after both token lifetimes plus retention. Revoked rows are retained for replay detection, deactivation/revocation flags are unchanged, and orphan sessions use their own nullable expiry. Parsed Go timestamps avoid lexical comparisons across UTC offsets. This repair runs during ordinary startup/periodic cleanup and needs no schema migration.

## Browser client configuration

Authorize/login/signup/magic-link handlers resolve `config.GetForClient` from the validated current registration. Signup policy applies to both the visible entry points and signed POST, including explicit true when globally disabled. Authorize SSO uses the requesting client's idle timeout (`0` infinite), while background IdP cleanup still uses the global timeout. Password/magic-link MFA bypass and MFA trusted-device UI/creation use the client policy; new records and cookies use its expiry. MFA resolves the registration from server-stored challenge login state before side effects and re-reads it on GET/POST; missing, malformed, unknown/inactive clients and changed redirect/scope/grant/PKCE policy fail closed through `client.ValidateAuthorization` rather than using global device policy. Existing device expiries are unchanged. Shared authenticated SSO remains independent from direct trusted-cookie bypass; `prompt=login` requests fresh authentication. Consent POST revalidates its signed authorization parameters before persisting consent or issuing a code. Code TTL overrides are resolved at final issuance, including consent, email verification, passkey and federation completion. `GetForClient` copies the global audience slice before appending client audiences so resolving a different client cannot overwrite an in-flight request's policy.

## Introspection caller authorization

`introspect.HandleIntrospect` requires authenticated confidential-client credentials, or a live admin-user bearer token with the `autentico-admin` audience, using the same audience validator as admin middleware. Public identifiers are rejected before token inspection, including Basic/form requests with arbitrary secrets. Client authentication failures return a Basic challenge; rejected admin-audience/role requests return a Bearer insufficient-scope challenge. Existing client ownership and caller/target liveness checks remain. Shared client authentication for other endpoints is unchanged. Discovery already advertises only client-secret Basic/post authentication for introspection.

## Last active administrator

`user.mutateUser` reserves SQLite's writer before checking whether demotion, deactivation or deletion would remove the final non-deactivated admin. Password hashing stays outside the writer; update snapshots are read inside it so omitted roles cannot restore a concurrent demotion. The check and all mutations commit together, including session revocation and hard-delete child cleanup; failed commits explicitly roll back or discard the connection. Admin handlers, immediate self-service deletion and deletion-request approval return `409 last_active_admin` without side effects. Inactive admins do not count as replacements. Pending passkey registration cleanup excludes admin accounts. No schema migration or recovery command is added.

## Account deletion confirmation

Immediate self-service deletion requires `current_password` verified by `user.ConfirmPassword`, including account lockout. Bcrypt runs outside the writer; current credentials and the shared failed-attempt budget are checked and updated under the writer to prevent concurrent guesses overwriting each other. The opaque confirmation, active account, live token and matching session are rechecked in the hard-delete transaction. A reset or revocation that wins the writer first invalidates in-flight deletion. The production POST route uses the authentication rate limiter. Passwordless accounts always use the existing admin-review request flow. Malformed JSON, trailing data and extra JSON values fail closed; denied immediate deletion preserves accounts and sessions. Successful immediate deletion logs `user_deleted` with the already-loaded user actor and `source: self` after commit, preserving attribution without a post-delete lookup. Credentials are never persisted in request reasons or audit details. The account-only `ProfileResponse` adds `has_password`; the UI uses it for the deletion mode and handles actual 201/204 outcomes. A pending request always means the account remains active and can be canceled regardless of the current global setting. No schema migration is required.

## Federation outbound requests

`safeHTTPClient` uses `net.Dialer.Control` to validate each resolved socket address before dialing, including discovery, token exchange, JWKS, redirects, retries and IPv6 fallback. Private/loopback/link-local/unspecified/multicast/CGNAT addresses are rejected, including mapped IPv4; DNS prechecks cannot authorize a later private connection. Environment proxies are not used and redirect chains stay bounded. `NewLoginHandler(nil)` always selects this restricted client; the CLI uses that default. An explicit client isolates local OIDC integration fixtures without changing global transport or adding a runtime bypass flag. The two-instance HTTP suite uses a compiled Go test-only CLI entry point with that local transport; separate tests use the unchanged production binary to assert real-route registration and blocked discovery. CI builds that test executable alongside the real UI assets and downloads it as a separate test artifact; local runs compile it when no prebuilt test binary is supplied. Private provider endpoints require a public endpoint for production federation.

## Magic-link account budget

`issueMagicLinkToken` obtains the SQLite writer before reading the latest challenge, including used/exhausted rows. A per-account 60-second request cooldown applies across clients. Replacements carry the failure count and cannot extend the original unexpired deadline; five incorrect codes suppress new emails until that window expires. Successful redemption does not clear failures within the window. A new expired window starts with zero failures after the cooldown. Previous-link invalidation and insertion commit together; generation or storage failure preserves the prior credential. Shared `magicLinkWrite` retains explicit rollback/discard after failed COMMIT for issuance and consumption. Email expiration text uses the actual stored deadline. Cleanup compares parsed expiry instants, preserving live used budget records across UTC offsets. No schema or configuration is added. The SMTP/HTTP regression waits through the real cooldown and covers resends across clients, exhaustion of both credentials and recovery after expiry.

## Shared browser authentication completion

`mfa.FinishLogin` revalidates the current client and active user, applies local MFA/trusted-device policy, creates a browser session only after authentication, then enforces consent before issuing a code. Password, signup, email verification, magic links, named/discoverable passkeys and federation all use it; the MFA handler enters the same finalizer only after consuming a verified challenge. Passkeys (even with UV) and federation remain primary credentials. Email proof avoids a duplicate email OTP but never bypasses required/voluntary TOTP. A session insertion failure cannot issue a code.

Routine schema 18 adds `idp_sessions.mfa_method`, default empty for preserved historical sessions. SSO and direct consent require evidence satisfying current MFA policy; enrollment alone proves nothing about a session. Verified TOTP/email methods and completed trusted-device logins are recorded. Fully authenticated trusted-device SSO retains the existing cross-client semantics. No TOTP, session or token is discarded by schema 18; major approval remains `15,17` for pre-v3 upgrades.

### Consent and authentication freshness

`pkg/consent` accepts ten-minute HMAC continuations issued by the login finalizer (`LoginURL`) or eligible authorize SSO (`RedirectToConsent`). They bind all authorize fields to the browser without exposing its session ID. GET/POST revalidate registration, local MFA, current idle/absolute limits and requested `max_age`; `pkg/idpsession/freshness.go` shares checks with authorize. Fresh login works with SSO disabled or reauthentication requested; SSO proofs do not bypass those controls. `prompt=none` returns an RP error without consent UI.

`pkg/authzsig` binds `prompt` and `max_age` through primary, MFA and recovery paths. Requests carrying neither retain ordinary pending-link signature compatibility. Tokens use original grant authentication time; signed refresh claims preserve it across rotation. Legacy refresh grants recover linked browser creation time or original password issuance; already-rotated unlinked legacy credentials require login. No schema migration or key is added. Old consent pages must restart authorization.

Client registration/update and both admin client forms permit only `response_types: ["code"]`. `/authorize` rejects all other response types before SSO or login, even for legacy registrations that listed unsupported types (#513). It also enforces the authorization_code grant before SSO issuance (#527). Editing legacy response metadata requires removing unsupported entries and explicitly selecting Code; field-level guidance prevents a generic API failure or silent enablement.

`pkg/devicecode.HandleDeviceAuthorization` uses the shared token-endpoint client authenticator: confidential clients supply Basic/form credentials, public clients identify themselves. Basic may omit body client_id; its failures return 401 with a Basic challenge, and malformed Basic cannot fall back to valid form credentials. Codes are bound to the authenticated client before existing grant/scope checks (#514).

`client.AuthenticateClientFromRequest` parses client credentials once from PostForm or an OAuth form-decoded Basic header. URL, repeated and multiple credential sets are rejected; malformed Basic never falls back. `ErrInvalidClientAuthenticationRequest` maps malformed requests to 400 invalid_request, while authentication failures retain endpoint policy and matching challenges. Token grants use the resolved registration's ClientID after Basic decoding. The helper leaves JSON introspection bodies unread and preserves separate admin-bearer handling. `utils.WriteBasicUnauthorized` and `WriteBearerUnauthorized` supply the required 401 challenges (#516, #529).

`client.ValidatePKCE` is shared by `/authorize` and `client.ValidateAuthorization`: unsupported methods and methods without a challenge fail before SSO or signed-flow completion, retaining public-client PKCE and configured S256 enforcement (#517).

PKCE method omission means `plain` per RFC 7636 §4.3: authorize normalizes it before signing/rendering/storing, the shared validator applies S256 enforcement to implicit plain on direct signed flows, and `authcode.CreateAuthCode` stores an explicit method for every new PKCE code. Historical unlabelled codes keep their original S256 binding until expiry. Discovery advertises plain only with enforcement disabled. Clients using implicit S256 must add the explicit method and restart pending authorizations; no schema change is needed (#518).

Discovery explicitly emits `request_uri_parameter_supported: false` (no omitempty). After validating the client and registered callback, authorize rejects nonempty request_uri with request_uri_not_supported before login or SSO and never fetches it. Empty/bare values are omitted per RFC 6749 §3.1 (#520).

Discovery advertises `response_modes_supported: ["query"]`. Authorize rejects nonempty modes other than query with invalid_request before SSO/login, after trusted callback validation. Empty/bare values use the default query mode; anonymous POST-to-GET redirects retain an explicit query request (#521).

## Federation browser correlation

`beginLoginFlow` persists a signed state's hash and a separate browser-cookie hash with a ten-minute deadline. Secure deployments use an HttpOnly, SameSite=Lax `__Host-autentico_federation` cookie (Path=/, no Domain); local HTTP uses `autentico_federation`, following the existing IdP secure-cookie setting. The binding is reused for independent pending tabs. `consumeLoginFlow` reserves SQLite's writer, rechecks expiry, deletes exactly one matching record and commits before discovery/exchange or local account changes. Failed COMMIT explicitly rolls back or discards the reserved connection; wrong browsers never consume an owner's state. Replay remains rejected across restarts and with a retained cookie.

The independent upstream nonce is FlowID and must match the verified ID token. FederationState.Nonce stays the RP nonce. Schema 19 only adds the indexed pending-flow table; routine startup/migration preserves tokens, sessions, TOTP ciphertext and replay/lockout state, with no new key or major approval. Old in-flight federation callbacks must restart. Cleanup compares Unix expiry seconds using the configured retention threshold (#473).

Introspection reads optional aud/jti from the submitted credential only after exact token-hash matching, ownership, revocation, expiry, session and user checks. Parsing those already-authenticated bytes does not establish activity or reapply current audience configuration. Audiences are returned as arrays; missing or invalid optional claims and opaque-token claims are omitted. No schema change is needed (#522).

Client registration resolves client_type and token_endpoint_auth_method together before issuing a secret: none without a type infers public; both omitted default confidential/basic. The shared resolver rejects contradictory create/update metadata with invalid_client_metadata, including direct CRUD calls. Client type is immutable during updates. ToInfoResponse reports effective legacy authentication metadata (public → none; confidential with absent/none → basic), without mutating stored type or secrets. Ordinary edits persist the corrected method, including disabled clients. Admin create/edit choices follow these rules. No migration is needed; scope/scopes interoperability remains separate (#523).

## Group and custom-claim auditing

Admin group CRUD, membership changes and custom-claim upsert/delete use `audit.Log` after successful mutation. Group events target `group`; membership details contain `user_id`. Claim events target the user and include only `claim_name`, never the value. Existing retention and best-effort audit-write behavior apply. Event constants, Admin UI filters and the docs-web event table must stay aligned. No schema migration is required.


## ForwardAuth

`pkg/forwardauth` registers explicitly allowlisted same-site or unrelated HTTPS origins in `protected_apps` and hash-only `forward_auth_sessions` (routine schema 21). Private trusted-proxy `/forward-auth/{id}/check` returns status-only results, or HTML GET/HEAD redirects with `redirect=1`. App-origin `/_autentico/{id}/start`, `/callback` and POST `/logout` bypass the check and backend. Each app has an atomically registered public client with fixed callback and S256 PKCE; callback reuses same-issuer authorization-code validation and atomically consumes the code with app-session insertion, without issuing OAuth tokens. Pending transactions use encrypted per-flow browser cookies derived from the persistent CSRF key. App cookies use Secure/HttpOnly/SameSite=Lax and `__Host-` on HTTPS. Every check validates current app/client/account policy and parent IdP freshness/MFA/revocation. Emit X-Auth-Email only for verified addresses, reject semicolon path parameters, evict old pending flows instead of locking out new logins, and recheck code expiry while holding the writer. Block private proxy/bootstrap prefixes on the public IdP vhost. Activity coalescing uses min(30s, positive idle timeout / 4). Copy identity and filtered Cookie response headers into the proxy's backend request; empty cookie sets use a harmless marker to force replacement. Manage apps through `/admin/api/protected-apps` or Admin → Protected Apps.

`python3 tests/proxy/run.py --binary ./autentico` runs real TLS Caddy, nginx and Traefik Docker proxies against the built production binary, real Chromium and an HTTP backend; `proxy-e2e` runs it in CI. Use `--site-mode cross-site` to run the same suite with distinct registrable sites and third-party cookies explicitly blocked; the default `same-site` mode preserves sibling-host coverage. Both modes run in the CI matrix. The protocol is documented in `rfc/forward-auth-cross-domain.md`; schema remains 21 with existing authorization codes as the handoff. The broad Go suite belongs in CI; local validation should focus on changed packages and these requested integration tests.


## Cookie name configuration (#575)

Bootstrap config names all browser cookies: the existing IdP-session and refresh-token keys plus `AUTENTICO_CSRF_COOKIE_NAME`, `AUTENTICO_TRUSTED_DEVICE_COOKIE_NAME`, `AUTENTICO_FEDERATION_COOKIE_NAME`, `AUTENTICO_PASSKEY_REGISTRATION_COOKIE_NAME`, and `AUTENTICO_FORWARD_AUTH_COOKIE_PREFIX`. New settings accept nonempty HTTP-token base names up to 128 ASCII bytes; reserved browser prefixes and effective name/prefix collisions fail startup before replacing Bootstrap. `config.HostCookieName` retains automatic `__Host-` on secure federation/passkey bindings and HTTPS app sessions/flows, with their existing root path, Secure, HttpOnly and no Domain. CSRF/trusted-device attributes and literal IdP/refresh naming are unchanged. Reads and deletion use configured names without authentication aliases; rename requires fresh browser state. ForwardAuth strips configured credentials and historical default families from backend Cookie headers. The harmless empty-cookie marker is a proxy request header value, never a browser cookie. No schema, runtime setting or localStorage key changes.

The real-proxy harness accepts `--cookie-names custom` alongside either site mode. CI retains default same-site coverage and runs cross-site coverage with all seven cookie names/prefixes customized. Tests resolve expected names from fixture metadata and prove custom CSRF login, IdP SSO, app/flow cookie lifecycle and backend stripping.

## Federation claim requirements (#579)

Routine schema 22 adds `federation_providers.claim_requirements` JSON TEXT with a checked array shape and `[]` default. `pkg/federation/requirements.go` owns typed decoding, validation and the shared tester/callback evaluator. Omitted updates preserve rules; explicit `[]` clears; JSON null is rejected. All rows must pass with strict string/boolean types; missing/null/wrong-type claims fail even negative operators. Names address literal top-level claims. Go regex uses search semantics (anchors for whole-string matching); limits are 32 rows, 256-byte names, 4096-byte strings, 1024-byte patterns and 64 KiB serialized rules. Empty regex is valid.

The callback checks after verified ID-token/nonce validation and before resolveUser. It reloads the provider after upstream exchange, rejects disabled/changed upstream credentials or invalid stored policy, and evaluates current rules for new and linked users. Logs expose only provider/index/category, never values or tokens. Admin responses omit requirements for malformed stored policies, expose a safe error marker and permit explicit repair; unrelated edits and echoed GET responses must not clear invalid rules. Provider create/update retain permissive top-level metadata decoding; rule objects and tester payloads remain strict. Blank/omitted client secrets preserve the existing secret on update.

`POST /admin/api/federation/test-claim-requirements` is admin-only and read-only, with a 64 KiB input bound and duplicate top-level sample-key rejection. Logical errors return failed rows; malformed payloads return 400. It uses no provider network access, persistence, accounts, sessions or issuance. The UI calls Go for validation/matching, preserves boolean false and warns this is not JWT verification. The isolated real-proxy Playwright suite covers admin creation/editing/testing; the two-process functional suite covers live login and policy changes. Admission rules do not revoke existing sessions, affect other login methods, or configure issued-token claims.

## Group custom claims (#586)

Routine schema 23 adds `group_claims` with `(group_id, claim_name)` as its key
and cascading group ownership. Admin GET/POST/DELETE endpoints at
`/admin/api/groups/{id}/claims` mirror user claims. Group-local reserved words
such as `role` are allowed because `userclaim.EffectiveClaimMapByUserID` emits
literal `group.claim` keys. It resolves membership and direct overrides in one
query, filters reserved top-level names, and serves access tokens, ID tokens,
and UserInfo under `custom_claims`; the independent `groups` scope is unchanged.
Direct user listings still show only direct claims. Individual group-prefixed
keys allow leading digits/hyphens and up to 229 characters for any valid group
prefix. Group local names remain 128 characters and values 4096 Unicode
characters. Group renames change emitted prefixes; old JWTs remain snapshots.
The shared Admin UI ClaimsDrawer supports both user and group wrappers. Group
claim audit events target groups and include only the local claim name.
The opt-in `merge_group_claims` setting drops the group prefix and emits
inherited claims as sorted, unique string arrays; reserved names are then the
only protection against a group-local `role`, so `EffectiveClaimsByUserID`
filters them on every row. Individual claims with a matching name replace the
inherited array with a one-element array.
Contract: `rfc/group-custom-claims.md`.

The isolated UI regression suite runs with a freshly built binary:
`AUTENTICO_TEST_BINARY=/absolute/path/autentico node node_modules/@playwright/test/cli.js test --config group-claims.config.ts`
from `tests/browser`. It uses a temporary working directory, configuration,
database, and an available port.

## Client access restriction (#609)

Routine schema 24 adds `clients.restrict_access` and the
`client_allowed_groups` / `client_allowed_users` join tables. Every path that
issues a user session, code or token for a client calls `client.CheckUserAccess`
with the current client and user after authentication: `mfa.finishLogin` (before
`FinalizeLoginWithMfa`, so a refused login creates no cookie), SSO in
`authorize.tryAutoLogin`, consent GET/POST, the token endpoint for every user
grant, device approval, and ForwardAuth `parentIdentity` on every check. New
issuance paths must call it too. The explicit flag makes deleted groups or users
fail closed; never infer restriction from non-empty lists. Built-in admin and
account clients are restrictable like any other; the admin API role check is
independent. Database errors
are server errors, never allows. ForwardAuth refusals return 403 without a login
redirect to avoid loops. Refusal audit details contain only `user_id` and
`flow`; ForwardAuth audits at callback, not per check. Contract:
`rfc/client-access.md`.
