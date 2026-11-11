# Client access restriction (#609)

This is an Autentico feature contract. RFC 6749 §4.1.2.1 and §5.2 supply the
error codes; which users a client admits is local policy, not an OAuth or OIDC
requirement. Requested in discussion #607; modeled on Authentik application
bindings with "any" evaluation.

## 1. Data

- `clients.restrict_access` (boolean, default `false`).
- `client_allowed_groups (client_id, group_id)` and
  `client_allowed_users (client_id, user_id)`, keyed on the pair, cascading on
  client, group and user deletion.

Migration 24 is routine and additive. Existing clients stay unrestricted.

## 2. Rule

When `restrict_access` is `false`, every user may authenticate to the client,
as before. When it is `true`, a user MAY authenticate only if they are listed in
the allowed users **or** are a member of **any** allowed group. With both lists
empty, nobody may authenticate.

The explicit flag exists so that deleting the last bound group or user fails
closed instead of silently opening the client to everyone.

The built-in `autentico-admin` and `autentico-account` clients MUST NOT be
restricted. Writes that would restrict them are rejected, and the check ignores
them, so a mistaken list can never lock administrators or account owners out.

## 3. Enforcement

The check runs for the current client, on current data, after the user has
authenticated, on every path that issues a user session, code or token:

| Path | Behavior when refused |
|---|---|
| Browser login (`mfa.FinishLogin`, all primary methods, after MFA) | Redirect to the client with `access_denied` (RFC 6749 §4.1.2.1). No IdP session, cookie or code is created. |
| SSO at `/oauth2/authorize`, including `prompt=none` | Redirect with `access_denied`. The existing IdP session is kept for other clients. |
| Consent screen (GET and POST) | Redirect with `access_denied`; no consent or code is stored. |
| Token endpoint: `authorization_code`, `refresh_token`, `password`, device code | `400 invalid_grant` (RFC 6749 §5.2). `access_denied` is not a token endpoint error. |
| Device approval (`/account/api/device/authorize`) | `403 access_denied`; the request stays pending so an allowed user can still approve it. |
| ForwardAuth check and callback | `403`, never a login redirect, so a refused user does not loop. Removing a user or group revokes access on the next check. |

A missing or inactive client fails closed. A database error while checking is
a server error, never an implicit allow. `client_credentials` has no user and is
unaffected. Access tokens already issued remain valid until they expire; refresh
is refused.

Wrong passwords are rejected before access is evaluated, so the response for an
unknown or wrongly authenticated user never reveals restriction state.

## 4. Account dashboard

`/account/api/apps` omits restricted applications the current user cannot open.

## 5. Administration

Admin client create, read, list and update include `restrict_access`,
`allowed_groups` and `allowed_users` (IDs). On update, omitted fields are
unchanged, a provided list replaces the stored list, and `[]` clears it. Lists
are deduplicated and capped at 1000 entries each. Unknown IDs reject the whole
request with `400 invalid_client_metadata`; the client row and lists are written
in one transaction, so a rejected request changes nothing.

## 6. Audit

Every refusal emits `client_access_denied` targeting the client, with the user as
actor and details limited to `user_id` and `flow` (the primary login method,
`sso`, `consent`, `device_code` or the grant type). Group names and list contents
are never recorded or returned in error responses.
