# Security Test Plan: Admin API Authorization and Privilege Escalation

## Target
`/admin/api/*` — `http://localhost:9999`

## Context from Proxy Traffic
Admin API uses Bearer token authentication. The admin token is issued to the `autentico-admin` client. Observed admin endpoints:

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | /admin/api/clients | 200 | List OAuth clients |
| POST | /admin/api/clients | 201 | Create client |
| GET | /admin/api/users | 200 | List users |
| POST | /admin/api/users | 201 | Create user |
| GET | /admin/api/groups | 200 | List groups |
| POST | /admin/api/groups | 201 | Create group |
| GET | /admin/api/settings | 200 | Get app settings |
| PUT | /admin/api/settings | 204 | Update settings |
| GET | /admin/api/sessions | 200 | List all sessions |
| GET | /admin/api/audit-logs | 200 | View audit logs |
| GET | /admin/api/stats | 200 | Dashboard stats |
| GET | /admin/api/federation | 200 | Federation config |
| GET | /admin/api/deletion-requests | 200 | User deletion requests |

## Tests

### 1. Vertical Privilege Escalation (HIGH)
**Why:** A regular user's access token should not work on admin endpoints.

- [ ] Use a non-admin user's access token (from `autentico-account` client) against `/admin/api/users` — should be 401/403
- [ ] Use a non-admin user's access token against `/admin/api/settings` — should be 401/403
- [ ] Use a non-admin user's access token to `POST /admin/api/clients` — should be 401/403
- [ ] Use an expired admin token — should be 401
- [ ] Use no Authorization header — should be 401

### 2. Horizontal Privilege Escalation / IDOR
**Why:** Admin endpoints may expose data from all users without proper scoping.

- [ ] `GET /admin/api/users` — does it expose password hashes, TOTP secrets, or other sensitive fields?
- [ ] Check if user IDs in responses are predictable/sequential vs random
- [ ] Can a lower-privilege admin modify a higher-privilege admin's account?

### 3. Admin API Input Validation
**Why:** Admin endpoints accept JSON bodies for creating/updating resources.

- [ ] Create a client with XSS in `client_name`: `<script>alert(1)</script>`
- [ ] Create a client with extremely long `client_id` or `client_name`
- [ ] Create a client with `redirect_uris` containing javascript: or data: schemes
- [ ] Create a user with SQL injection in username: `admin' OR '1'='1`
- [ ] Update settings with invalid values — negative token expiry, empty issuer, etc.
- [ ] Create a client with duplicate `client_id` — check error handling

### 4. Mass Assignment / Extra Fields
**Why:** Sending unexpected fields in JSON bodies may set internal properties.

- [ ] `POST /admin/api/users` with extra fields: `"is_admin": true`, `"role": "admin"`
- [ ] `POST /admin/api/clients` with extra fields: `"client_secret": "known"` for a public client
- [ ] `PUT /admin/api/settings` with fields not shown in the UI

### 5. Admin API Rate Limiting
- [ ] Rapidly call `POST /admin/api/users` — is there rate limiting?
- [ ] Rapidly call `GET /admin/api/audit-logs` with varying offsets — data exfiltration speed

## Key Proxy Flows
| Flow ID | Endpoint | Notes |
|---------|----------|-------|
| kxP3jL | POST /admin/api/clients | Client creation with Bearer |
| IbWUCe | POST /admin/api/users | User creation |
| iQYYcn | POST /admin/api/groups | Group creation |
| JzfyFZ | PUT /admin/api/settings | Settings update |
| kGh5KR | POST /oauth2/token | Admin token exchange |
