# Real proxy end-to-end tests

Run on Linux with Docker, OpenSSL, Node and the project's pnpm version:

```bash
make build
pnpm --dir tests/browser install --frozen-lockfile
pnpm --dir tests/browser exec playwright install chromium --with-deps
python3 tests/proxy/run.py --binary "$PWD/autentico" --logs /tmp/forward-auth-logs
```

The same command runs in the `proxy-e2e` CI job. It uses the supplied production
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
MFA, same-site SSO, query preservation, host-scoped cookies and credential
stripping, application-cookie preservation, forged identity/forwarding headers, verified-email-only identity, semicolon path
traversal, long-return pending-cookie budgets, forced same-site image logins with pending-flow eviction, private-route
blocking on public Caddy/nginx IdP vhosts,
noninteractive denial, unsafe methods, unsafe return destinations, path policy,
wrong-browser completion, altered state/code, callback replay, real expiry,
app disable/re-enable, local logout, central/user revocation, account disable,
changed MFA policy, active use with short idle limits, IdP domain migration with
continued administration and denied stale registrations, cross-app credentials, parallel tabs, pending callbacks and
sessions across restart, and fail-closed authentication-service outages.
