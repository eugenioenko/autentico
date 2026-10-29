# Real proxy end-to-end tests

Run on Linux with Docker, OpenSSL, Node and the project's pnpm version:

```bash
make build
pnpm --dir tests/browser install --frozen-lockfile
pnpm --dir tests/browser exec playwright install chromium --with-deps
python3 tests/proxy/run.py --binary "$PWD/autentico" --site-mode same-site --logs /tmp/forward-auth-logs
python3 tests/proxy/run.py --binary "$PWD/autentico" --site-mode cross-site --cookie-names custom --logs /tmp/forward-auth-cross-site-logs
```

Both modes run independently in the `proxy-e2e` CI matrix. It uses the supplied production
binary, an isolated database and generated keys, three pinned Docker images
(Caddy 2.10.2, nginx 1.28.0, Traefik 3.5.0), distinct HTTPS browser hostnames,
and a real HTTP backend that counts forwarded requests. Chromium's test-only
DNS rule maps those hostnames to loopback without modifying system hosts.
Certificates are self-signed in this fixture only. Auth state is changed through
public admin APIs; there is no fixture-only authentication route or database
manipulation. Attack tests pause a real login redirect before callback redemption.

The fixture reserves loopback TCP ports 25443–25446 and 25997–25999, plus Caddy's
25443 UDP port. Run one instance at a time. Host networking requires Linux.
Only containers named with this invocation's random suffix are removed. Auth
outage/restart tests are controlled by an authenticated loopback-only harness
endpoint; no control endpoint is added to Autentico. Processes and containers
are stopped in finally blocks. Use the logs directory and Playwright traces to
diagnose a failure; these test artifacts can contain test-only browser secrets.

Coverage includes successful browser login and POST forwarding, actual TOTP
MFA, same-site and cross-site SSO, query preservation, host-scoped cookies and credential
stripping, application-cookie preservation, forged identity/forwarding headers, verified-email-only identity, semicolon path
traversal, long-return pending-cookie budgets, forced same-site image logins with pending-flow eviction, private-route
blocking on public Caddy/nginx IdP vhosts,
noninteractive denial, unsafe methods, unsafe return destinations, path policy,
wrong-browser completion, altered state/code, callback replay, real expiry,
app disable/re-enable, local logout, central/user revocation, account disable,
changed MFA policy, active use with short idle limits, safe IdP domain migration, unsafe IdP/app hostname collisions with
continued administration and denied unsafe registrations, cross-app credentials, parallel tabs, pending callbacks and
sessions across restart, and fail-closed authentication-service outages.

The default `same-site` layout uses `auth.example.test` and sibling app hosts.
The `cross-site` layout keeps that IdP but places each app on a distinct site:
`caddy.caddy-app.test`, `nginx.nginx-app.test`, `traefik.traefik-app.test`.
The harness renders those hosts into the complete proxy configurations and
issues a fixture certificate covering each site. Chromium maps `*.test` to
loopback. Every test page in cross-site mode explicitly blocks third-party
cookies via CDP, including metadata/grace and heuristic exceptions. A dedicated
negative control proves a SameSite=None cookie is sent first-party and withheld
on an unrelated-site image request, then completes normal fresh login and SSO.
No production endpoint is mocked for this control. Browser assertions also
check bounded redirect chains, central/app credential isolation, copied flow
cookies at wrong destinations, pending-completion policy changes and clean
backend requests/referrers. Normal fresh-login, MFA and SSO tests run entirely
through the browser; attack tests pause only the final login redirect.

`--cookie-names custom` overrides all seven cookie settings in the real server's
process environment, including CSRF, IdP, refresh, trusted-device, federation,
passkey-registration and ForwardAuth. Default names remain the harness default.
The CI cross-site job uses custom names; the same-site job retains defaults.
Login forms prove the custom CSRF cookie is used, SSO/logout use the custom IdP
name, and app login/parallel flows/rotation/restart/logout exercise custom app
cookie names. Backend assertions also withhold legacy default credentials.
