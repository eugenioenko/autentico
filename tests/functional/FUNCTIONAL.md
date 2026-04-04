# Functional Test Suite

Black-box tests that build the real Autentico binary, run CLI commands (`init`, `onboard`), start the server as a process, and hit every API endpoint with HTTP requests.

## Running

```bash
cd tests/functional
pnpm install
pnpm test
```

The setup automatically builds the binary (if not already built), creates a temp directory with a fresh `.env` and database, onboards an admin account, starts the server, and tears everything down after tests complete.

## Coverage

**104 tests** across **16 test files** covering **47 of 58 Swagger endpoints** (81%).

| File | Tests | Endpoints covered |
|------|-------|-------------------|
| discovery.test.ts | 3 | `GET /.well-known/openid-configuration`, `GET /oauth2/.well-known/jwks.json` |
| token.test.ts | 3 | `POST /oauth2/token` (ROPC, refresh, revocation) |
| userinfo.test.ts | 3 | `GET /oauth2/userinfo` |
| client.test.ts | 5 | `POST /oauth2/register`, `GET /oauth2/register` |
| auth-flow.test.ts | 1 | `GET /oauth2/authorize`, `POST /oauth2/login`, `POST /oauth2/token`, `GET /oauth2/userinfo` |
| admin-users.test.ts | 18 | `POST/GET/PUT/DELETE /admin/api/users`, `POST /admin/api/users/{id}/unlock` |
| admin-clients.test.ts | 17 | `POST/GET/PUT/DELETE /admin/api/clients` |
| admin-sessions.test.ts | 6 | `GET/DELETE /admin/api/sessions` |
| admin-settings.test.ts | 6 | `GET/PUT /admin/api/settings`, `GET /admin/api/settings/export` |
| admin-stats.test.ts | 4 | `GET /admin/api/stats`, `GET /admin/api/audit-logs` |
| introspection.test.ts | 5 | `POST /oauth2/introspect` |
| logout.test.ts | 5 | `GET/POST /oauth2/logout` |
| account-api.test.ts | 7 | `POST/GET/DELETE /account/api/deletion-request` |
| admin-deletions.test.ts | 6 | `GET/DELETE /admin/api/deletion-requests`, `POST /admin/api/deletion-requests/{id}/approve` |
| admin-federation.test.ts | 12 | `POST/GET/PUT/DELETE /admin/api/federation` |
| health.test.ts | 4 | `GET /healthz`, `GET/POST /onboard` |

## Testing pattern

Every resource follows a CRUD lifecycle:

1. **POST** — create, verify 201 + response body
2. **GET** (list) — verify created resource appears
3. **GET** (by ID) — verify fields match
4. **PUT** — update a field, verify 200
5. **GET** — verify update persisted
6. **DELETE** — verify 204
7. **GET** — verify 404 after deletion

Each file also includes negative/error tests:

- **Auth errors:** No token → 401, invalid token → 401
- **Validation errors:** Empty body → 400, missing required fields → 400, invalid values → 400
- **Not found:** GET/PUT/DELETE nonexistent ID → 404
- **Business logic:** Duplicate creation, invalid enums, RFC-specific error codes

## Endpoints not covered

| Endpoint | Reason |
|----------|--------|
| `POST /admin/api/settings/test-smtp` | Requires SMTP server |
| `GET/POST /oauth2/mfa` | Requires TOTP enrollment |
| `GET/POST /oauth2/signup` | Requires `allow_self_signup` + CSRF |
| `GET/POST /oauth2/passkey/*` | Requires WebAuthn browser API |
| `GET/POST /oauth2/forgot-password` | Requires SMTP |
| `GET/POST /oauth2/reset-password` | Requires SMTP |
| `POST /admin/api/settings/import/preview` | Requires specific import payload format |
| `POST /admin/api/settings/import/apply` | Requires specific import payload format |

These are covered by Playwright browser tests (`tests/browser/`) or Go e2e tests (`tests/e2e/`).

## Discoveries

### API strengths confirmed

- **OAuth 2.0 / OIDC compliance:** Discovery, JWKS, authorization code flow, token exchange, refresh, revocation, introspection — all work correctly end-to-end against a real running instance
- **RFC 7591 error codes:** `invalid_client_metadata` and `invalid_redirect_uri` returned correctly on client registration validation failures
- **Auth guards:** Every admin endpoint correctly rejects requests without a valid admin bearer token (401)
- **CRUD consistency:** All resources (users, clients, sessions, settings, federation providers, deletion requests) follow consistent create/read/update/delete patterns
- **Logout compliance:** RP-Initiated Logout 1.0 — POST with `id_token_hint`, GET with `post_logout_redirect_uri`, unregistered URI rejection all work correctly
- **Token lifecycle:** ROPC → refresh → revoke → verify rejection at userinfo — complete chain verified

## Tech stack

- **Vitest** — test runner
- **TypeScript** — test language
- **Node.js fetch** — HTTP client (no extra dependencies)
- **pnpm** — package manager

## CI

Functional tests run as a separate job in `.github/workflows/ci.yml`, downloading the pre-built binary artifact from the `build` job. The binary is built once and shared with the Playwright smoke tests.
