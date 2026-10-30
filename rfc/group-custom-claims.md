# Group custom claims (#586)

This is an Autentico feature contract. OIDC Core §5.1.2 and §5.3.2 permit
additional claims; §5.4 supplies the scope mechanism. The namespace and
precedence rules below are local behavior, not requirements imposed by OIDC.

## 1. Scope

Administrators manage custom string claims on groups through the Admin UI and
API. Members inherit those claims without copying them to individual user rows.
Applications interpret claims and enforce their own access rules. This feature
does not introduce role definitions, actions, or authorization decisions.

## 2. Effective claims

An inherited claim MUST be emitted under the literal top-level key
`<current group name>.<local claim name>`. Dots do not create nested JSON.
For example, group `app1` with `role=user` emits `"app1.role": "user"`.
Group names are unique and contain no dots, so two groups cannot produce the
same inherited key. Claim and group names are case-sensitive.

An individually assigned claim with the same full key MUST override the group
value, including when the individual value is an empty string. Individual claims
MAY supply a group-prefixed key without any membership in that group. Removing
an individual override reveals the current inherited value, if membership and
the group claim still exist. Admin user-claim listings MUST continue to return
only individual assignments.

## 3. Validation and protected claims

Local group claim names MUST match `^[a-zA-Z_][a-zA-Z0-9_.:/-]*$` and be
1–128 characters. Values MUST follow the existing custom-claim string contract:
empty values are allowed and the maximum is 4096 Unicode characters.

Group-local names such as `role`, `email`, and `sub` MAY be used because their
emitted keys are always prefixed. The effective resolver MUST exclude reserved
top-level claim names even if an invalid individual row bypassed API validation.
Neither source may replace Autentico's standard or structural claims.

Individual claims MUST accept the emitted group-prefixed form, including group
names beginning with digits or hyphens. Such keys MAY be up to 229 characters
(100-character group name, dot, 128-character local claim name). Existing bare
claim syntax and its 128-character limit remain supported.

## 4. Administration and persistence

`group_claims` MUST have a primary key of `(group_id, claim_name)` and a foreign
key to `groups(id)` with `ON DELETE CASCADE`. Migration 23 is a routine additive
migration and MUST preserve existing user claims and memberships.

All endpoints MUST use existing admin authentication:

| Method | Path | Success |
|---|---|---|
| GET | `/admin/api/groups/{id}/claims` | 200, local names and values in the existing claim-list envelope |
| POST | `/admin/api/groups/{id}/claims` | 201, upsert `{name, value}` |
| DELETE | `/admin/api/groups/{id}/claims/{name...}` | 200 |

Malformed requests MUST return 400. Missing groups MUST return 404 on listing or
upsert; missing claims MUST return 404 on deletion. Database failures MUST return
500. Local claim names containing slashes MUST be percent-encoded in deletion
URLs. Deleting a group MUST remove its stored claims as well as memberships.

The group claims editor MUST show emitted names, support adding/replacing and
removing claims, and explain individual overrides and the required scope.
Renaming a group MUST change its inherited claim prefix; the edit UI MUST explain
that behavior. Explicit individual keys are not renamed automatically.

## 5. Scope and freshness

Access tokens, ID tokens, and UserInfo MUST resolve the same effective map only
when `custom_claims` is granted. The `groups` scope is independent and MUST NOT
be required for inherited custom claims. No new scope or discovery capability
is introduced. Client-credentials tokens have no user and inherit no claims.

New and refreshed tokens MUST reflect current memberships, group names, claims,
and individual overrides. UserInfo MUST resolve current data. Existing JWTs
remain snapshots until expiry; changing a claim does not rewrite or revoke them.
Resolution failures MUST fail the operation rather than return partial claims.

## 6. Audit

Successful claim upserts and deletions MUST emit `group_claim_upserted` and
`group_claim_deleted`, targeting the group. Details MUST identify `claim_name`
and MUST NOT contain claim values. Rejected or failed mutations MUST NOT emit
success events. Existing audit retention and best-effort storage apply.
