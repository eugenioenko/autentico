# Cross-domain ForwardAuth (#581)

## Decision

Extend the existing ForwardAuth authorization-code protocol to explicitly
registered HTTPS application origins on unrelated sites. Registration by an
authenticated administrator is the allowlist; no wildcard domains, new grant,
global cookie domain, CORS permission, configuration switch or schema is added.
Production app hostnames must still differ from the IdP hostname, since cookies
do not isolate ports. Literal loopback HTTP remains a development exception,
and the app and IdP origins must differ even on loopback.

The [GateKeeper example](https://gatekeeper.xyzlab.dev/integrations/cross-domain.html)
uses an opaque single-use handoff followed by an app-host session cookie.
Autentico's existing authorization code supplies that handoff, with state,
nonce, S256 PKCE and an encrypted initiating-browser cookie. A handoff code is
sensitive until consumed, even though it contains no user data.

## Browser and proxy flow

1. A browser visits `https://dashboard.otherdomain.net/reports?month=10`.
   The proxy makes its private status check. APIs and unsafe methods receive
   noninteractive denial; an HTML GET/HEAD may start a browser login.
2. The browser visits the app-host `/_autentico/{id}/start` route. The proxy
   sends this route directly to Autentico, overwriting original host/protocol.
   Autentico validates the registered origin and relative destination, sets an
   encrypted, host-only flow cookie, and redirects to its central authorize URL.
3. On `https://auth.example.com`, existing login/eligible SSO, verification,
   consent and MFA policy apply. The IdP cookie is sent only to the IdP host.
4. A top-level GET navigation returns an authorization code and state to the
   exact registered app-host callback. `SameSite=Lax` permits the initiating
   flow cookie on this safe top-level cross-site navigation. No iframe,
   background cross-site fetch, third-party cookie, or POST callback is needed.
5. The app proxy routes the callback directly to Autentico without an auth
   precheck or protected-backend request. The handler requires the initiating
   browser cookie and app/origin/state/nonce/PKCE binding before consuming the
   code. Code consumption, expiry recheck and app-session insertion are atomic.
6. Autentico returns the app's host-only Secure/HttpOnly/SameSite=Lax session
   cookie, deletes the completed flow cookie and redirects to the clean relative
   destination. A normal proxy check now authorizes the backend request.

The start and callback responses pass through the app proxy so Set-Cookie
applies to the app hostname. Private calls target Autentico directly, never its
public IdP vhost. Public IdP routes block both private endpoint families.
Caddy/Traefik may relay browser redirects from checks; nginx retains status-only
auth subrequests and a separate login redirect. Existing tested configurations
apply with an unrelated app hostname and that app's registration ID.

## Storage, lifetime and failure boundaries

Reuse `protected_apps` and its fixed-callback public `clients` registration,
`auth_codes` for the expiring single-use handoff, `idp_sessions` for central
authentication evidence, and hash-only `forward_auth_sessions` for app access.
Pending browser transactions remain encrypted cookies. Routine schema stays 21.

App sessions retain per-request parent freshness, account, client, app and MFA/
email checks. Local logout revokes that app session; central logout or explicit
parent/user revocation invalidates linked apps on their next check, even though
another domain cannot delete their browser cookies. Idle/absolute expiry,
disabled apps/users and service errors continue to fail closed. Separate flows
support parallel tabs; cookie count/byte budgets evict oldest pending flows.
Persistent keys/database preserve unexpired flows and replay protection across
restarts. Moving the IdP to another unrelated hostname does not invalidate a
still-safe app registration; moving it onto the app hostname makes that
registration unsafe and authentication must reject it while administration
remains available.

Proxy access/error logging and analytics must exclude callback queries and
cookies. Callback responses retain no-store/no-referrer headers and contain no
application content. Checks remove authentication cookies before the backend.
Only the temporary code/state visit the app-origin callback: no central cookie,
access token or refresh token is delivered to the protected backend. Registered
apps are trusted administrators' destinations; this does not add authorization
groups or CSRF protection for applications' own state-changing endpoints.

## Validation

Run the production binary and real Caddy/nginx/Traefik Docker binaries with TLS
and Chromium in both sibling-host and unrelated-site layouts. In cross-domain
mode each proxy app uses a different registrable site from the IdP and the
other apps. Explicitly block third-party cookies, disable browser exceptions,
and prove a SameSite=None probe cookie is withheld as a subresource but remains
available during a first-party navigation. Keep normal login/SSO flows fully
browser-driven.

Reuse the complete black-box suite for fresh login, real MFA, SSO on/off,
queries, cookie/identity isolation, path and proxy trust, parallel tabs,
concurrent/replayed/expired callbacks, restart, app/user/parent revocation,
timeouts, outages and admin UI. Add cross-site credential-leak and redirect-loop
assertions, independent browser attacks, wrong app/destination binding and
current-policy changes before redemption. Unit tests cover canonical origin
registration, explicit destination authorization and transaction bindings.

## References

- RFC 6749 §§3.1.2, 4.1.2, 4.1.3: exact callbacks, client binding, single use.
- RFC 7636 §4.6: PKCE verification.
- [RFC 9700 §§2.1, 4.7, 4.11](https://www.rfc-editor.org/rfc/rfc9700.html):
  browser correlation and redirect validation.
- RFC 6265 §8.5 and [SameSite cookie behavior](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value).
- [Traefik ForwardAuth](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/),
  [Caddy forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth),
  [nginx auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).
