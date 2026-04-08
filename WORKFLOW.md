# Feature Development Workflow

Checklist for implementing new features in Autentico. Every step applies unless explicitly marked as conditional.

---

## 1. Specification

- [ ] Read the relevant RFC/spec sections before writing any code
- [ ] Identify all MUST/SHOULD/MAY requirements that apply
- [ ] Check if a GitHub issue exists; create one if not (prefix title with `feat:`)

## 2. Implementation

- [ ] Implement the feature following existing package conventions (`model.go`, `handler.go`, CRUD files, `service.go`)
- [ ] Annotate every return path (success, error, redirect) with an inline RFC comment referencing the exact spec section:
  ```go
  // OIDC Core §3.1.3.6: at_hash MUST be computed as base64url(left-half(SHA-256(access_token)))
  ```
- [ ] Annotate every request validation check with the spec clause that requires it:
  ```go
  // RFC 7636 §4.1: code_verifier MUST be 43-128 characters
  ```
- [ ] Add Swagger annotations (`@Summary`, `@Param`, `@Success`, `@Failure`, `@Router`) to new or changed handlers

## 3. Testing

Four test layers exist. Not every feature needs all four — pick based on what the feature touches.

| Layer | Location | Language | Runs with | When to add |
|-------|----------|----------|-----------|-------------|
| **Unit** | `pkg/*/…_test.go` | Go | `make test` | Always. Every feature needs unit tests for its logic, validation, and error paths. |
| **E2E** | `tests/e2e/` | Go | `make test` | When the feature spans multiple endpoints in a single flow (e.g., authorize -> login -> token). Uses `httptest.Server` with in-memory DB. |
| **Functional** | `tests/functional/` | TypeScript (Vitest) | `make test-functional` | When you need black-box HTTP testing against a real running server. Good for verifying the external API contract, headers, status codes, and response shapes without internal knowledge. |
| **Browser** | `tests/browser/` | TypeScript (Playwright) | manual | When the feature has a UI component (login page, signup form, MFA prompt, consent screen). Tests real browser interactions including JavaScript, cookies, and redirects. |

For each layer you add tests to:
- [ ] **Positive test** — happy path works as specified
- [ ] **Negative test** — violations are rejected with the correct error
- [ ] Run `make test` — all Go tests pass
- [ ] Run `make lint` — no new lint warnings

## 4. Configuration (if applicable)

- [ ] **Bootstrap config** (`pkg/config/config.go`) — if the feature adds env vars:
  - Add field to `BootstrapConfig` struct
  - Read from env in `InitBootstrap()`
  - Add to `.env` template in `pkg/cli/init.go`
- [ ] **Runtime config** (`pkg/config/config.go`) — if the feature adds runtime settings:
  - Add field to `Config` struct
  - Add default in `appsettings.EnsureDefaults()`
  - Load in `appsettings.LoadIntoConfig()`
- [ ] **Per-client overrides** — if the setting should be overridable per client:
  - Add nullable field to `ClientOverrides`
  - Handle in `GetForClient()`

## 5. RFC Compliance

- [ ] Update the MUST/SHOULD/MAY table in `rfc/rfc.md` for the relevant spec phase
- [ ] Review the spec's Security Considerations section — add checklist items for anything actionable
- [ ] Verify `/.well-known/openid-configuration` advertises any new capabilities or endpoints

## 6. UI (if applicable)

- [ ] **Admin UI** (`admin-ui/`) — if the feature adds a new runtime setting, add it to the relevant settings page so admins can configure it
- [ ] **Account UI** (`account-ui/`) — if the setting or feature is visible to end users (e.g., MFA, passkeys, trusted devices, profile fields), add or update the relevant section in the account self-service UI

## 7. Documentation

- [ ] **README.md** — update feature tables, configuration tables, endpoint lists, or security section as needed
- [ ] **docs-web** — update the relevant page(s) under `docs-web/src/content/docs/`:
  - `configuration/bootstrap.mdx` for new env vars
  - `configuration/runtime-settings.mdx` for new runtime settings
  - Feature-specific pages (authentication, protocol, security, etc.)
- [ ] **CLAUDE.md** — update if the feature adds new packages, config values, CLI commands, or changes architecture
- [ ] **Swagger** — run `make generate-docs` if handler annotations changed

## 8. PR

- [ ] Create a feature branch (`feat/description`)
- [ ] Commit with a descriptive message (e.g., `feat: add at_hash claim to ID tokens`)
- [ ] PR description includes:
  - Summary (what and why)
  - Test plan (what was tested, how to verify)
- [ ] All CI checks pass

---

## What NOT to do

- Don't add features, config, or abstractions beyond what the issue requires
- Don't add SAML, LDAP, SCIM, or enterprise-scale features — they don't align with the project philosophy (see README "Who Autentico Is For")
- Don't skip negative tests — a positive-only test doesn't prove the guard works
- Don't remove or replace existing RFC annotations — if a reference needs correcting, add the corrected one alongside it
- Don't defer discovery updates — fix them in the same PR that adds the feature
