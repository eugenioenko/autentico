# API Fuzzing (Schemathesis)

Property-based, spec-driven fuzzing of the Autentico HTTP API. Schemathesis reads
the live OpenAPI spec from `/swagger/doc.json`, generates malformed / boundary /
random requests for every documented operation, and asserts the server never
returns a 5xx, never crashes, and honours its own schema and auth.

This is the "chaos monkey for the API" equivalent — the spec drives it instead of
random command sequences, so it covers the whole surface without hand-written
cases.

## Requirements

- Docker (the Schemathesis CLI runs from a pinned image)
- `python3`, `curl` on the host
- Linux (`run.sh` uses `docker --network=host`)

## Run

```bash
make schemathesis                 # both profiles
PROFILE=public make schemathesis  # unauthenticated only
PROFILE=admin  make schemathesis  # admin API only
```

`run.sh` builds the binary if missing, creates a throwaway server (temp DB, rate
limiting disabled, insecure cookies), onboards an admin, runs the fuzzer, and
tears everything down. Nothing touches your real `autentico.db` or `.env`.

JUnit reports land in `schemathesis/report/` (gitignored).

### Profiles

| Profile  | Auth                          | Paths                                            |
|----------|-------------------------------|-------------------------------------------------|
| `public` | none                          | everything except `/admin/*` and `/account/*`   |
| `admin`  | clean ROPC bearer token       | `/admin/api/*` only, minus `/admin/api/settings*` |

`/admin/api/settings*` is excluded so a fuzzed `PUT` can't disable the admin
bearer auth, CORS, or SMTP mid-run and turn the rest of the run into noise.
`/account/*` is skipped entirely — it needs a browser session, not a bearer
token; cover it with the browser/e2e suites instead.

### Env overrides

| Var            | Default                          | Meaning                                  |
|----------------|----------------------------------|------------------------------------------|
| `PROFILE`      | `both`                           | `public` \| `admin` \| `both`            |
| `PORT`         | `19998`                          | server port                              |
| `MAX_EXAMPLES` | `50`                             | generated cases per operation            |
| `MAX_FAILURES` | `50`                             | stop after N failures                    |
| `ST_IMAGE`     | `schemathesis/schemathesis:4.26.1` | CLI image (bump to upgrade)             |
| `ST_ARGS`      | –                                | extra args for `schemathesis run`        |
| `KEEP_SERVER`  | –                                | `1` leaves the server running on exit    |

Example — re-run a single failing operation with more cases:

```bash
MAX_EXAMPLES=500 ST_ARGS='--include-path-regex /admin/api/users' PROFILE=admin make schemathesis
```

## CI

`.github/workflows/schemathesis.yml` runs the same script on
`workflow_dispatch` only (manual trigger from the Actions tab). It takes
`profile` and `max_examples` inputs and uploads the JUnit reports as an artifact.
It is not part of the PR gate — run it on demand or before releases.

## Complementary layers

- **Native Go fuzz tests** (`go test -fuzz`) for the security-critical parsers —
  redirect URI validation, PKCE verifier, JWT / bearer parsing, `authzsig` HMAC.
  Cheaper and catch panics at the unit level.
- **OWASP ZAP** for the active-scanner / known-attack angle.
- **k6** (`make stress-*`) for load and rate-limit behaviour.
