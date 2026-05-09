# Changelog

## v2.0 (unreleased)

### Breaking Changes

#### List endpoints return paginated response objects

**Affected endpoints:** All admin list endpoints (`/admin/api/users`, `/admin/api/groups`, `/admin/api/clients`, `/admin/api/federation`, `/admin/api/sessions`, `/admin/api/audit`, `/admin/api/tokens`, `/admin/api/deletions`)

**Before (v1.x):**
```json
[
  { "id": "...", "username": "..." },
  { "id": "...", "username": "..." }
]
```

**After (v2.0):**
```json
{
  "items": [
    { "id": "...", "username": "..." },
    { "id": "...", "username": "..." }
  ],
  "total": 42
}
```

**Migration:** Update API consumers to read `.items` instead of the root array, and use `.total` for pagination UI.

#### Account API requires audience claim

**Affected endpoints:** All `/account/api/*` endpoints

**Before (v1.x):** Any valid access token could call account API endpoints.

**After (v2.0):** Tokens must include `autentico-account` or `autentico-admin` in the `aud` (audience) claim. Tokens without a matching audience are rejected with 401.

**Migration:** Ensure clients that need account API access have `autentico-account` in their `allowed_audiences` configuration, or use the built-in `autentico-account` / `autentico-admin` clients.
