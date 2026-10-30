# Migration regression tests

Run the black-box suite with:

```bash
go test -count=1 -v ./tests/migrations
```

The suite builds the real application binary and invokes its CLI in subprocesses
against file-backed SQLite databases. Historical SQL prepares fixtures; upgrades
never call internal migration functions from the test process.

Coverage includes all schemas 1–14 in WAL and rollback-journal mode, populated
and empty databases, startup and approval behavior, committed WAL writes, pinned
readers, partial backup writes, SQL/deletion/commit failures, byte-for-byte
restoration and retry, process interruption, concurrent migrators, damaged
backups, invalid database files, file permissions, and new-volume initialization.
The Linux partial-write case uses a real kernel file-size limit and also works
when the suite runs as root. Existing account data and TOTP enrollment must
survive. Schema 17 encrypts active, pending and deactivated seeds without resetting enrollment, replay or lockout state. Missing or malformed keys must leave the database byte-for-byte unchanged. Encryption update/commit failures and process interruption restore the original enrollments and allow retry. Real post-upgrade login and restart tests prove the existing authenticator still works and replay state persists. Wrong keys reject startup and migration. Schema 17/18 fixtures cover automatic startup, interactive migration and unattended migration in WAL and DELETE modes: a wrong valid key must preserve the old schema and enrollment state, and restoring the original key allows retry. Schema 15 discards old tokens, OAuth/SSO sessions and pending login grants; schema 17 alone preserves sessions.

Schema 18 is a routine additive upgrade. Real CLI and automatic-start tests
upgrade schema 17 in both journal modes, preserve browser sessions and trusted
devices, and verify that historical sessions receive empty MFA evidence rather
than claiming that a second factor was completed. No major approval, backup or
session invalidation is required for this upgrade alone.

Schema 19 adds only indexed pending federation flows. Black-box schema-18 upgrades use explicit CLI migration and automatic startup in WAL/rollback-journal modes, preserving TOTP ciphertext, enrollment, replay/lockout counters, token hashes, browser MFA evidence and trusted devices. Index-collision failures after table creation roll back partial DDL and version, preserve user data and allow retry. The real two-instance HTTP suite additionally verifies pending login and consumed-state replay protection across server restarts.

Schema 20 hashes trusted-device cookies while assigning separate public IDs. Black-box upgrades preserve existing cookies, device metadata/expiry, token hashes and MFA state in both journal modes through startup and CLI migration. Failures roll back the schema and transformed rows so the same database can be retried.

CI runs the real database and CLI migration suite on Linux in the `test` job,
including paths containing spaces, Unicode, and URI-reserved characters.
The functional CI job also runs the Docker Compose migration test against the
same built binary used by the HTTP tests, including a root-owned `0640` config
that remains readable by the service group after `init` adds the key.

The migration package additionally tests routine automatic migrations and
approval of multiple pending major migrations. Endpoint tests in
`tests/e2e/token_storage_test.go` exercise storage, metadata, MFA refresh, and
rejection of database hashes as HTTP credentials.

Go source overlays build hypothetical future CLI versions without modifying the
working tree. These verify that the deployment command remains noninteractive
for a later routine upgrade while a new major schema requires separate approval.

## Docker Compose smoke test

As a non-root user on a Unix host with Docker Compose, Python 3, and a Docker daemon:

```bash
CGO_ENABLED=0 go build -o /tmp/autentico-migration-smoke .
python3 tests/migrations/docker_smoke.py --binary /tmp/autentico-migration-smoke
```

This starts isolated containers using the Debian runtime and the newly built
binary, with the same entrypoint, working directory, and database mount as the
application image. It checks missing-key refusal, safe key addition through `init`, retained service ownership of the existing configuration, encrypted enrollment preservation, startup refusal, headless approval, automatic
restoration after an injected failure, preserved host ownership, successful
retry, startup under the service UID after a root-run migration, and idempotent
deployment-job retry. The test
creates its own temporary data and Compose project and cleans them up afterward.
An existing compatible runtime image can be supplied with `--runtime-image`.

Schema 21 adds protected applications and app-scoped ForwardAuth sessions without changing existing credentials. Black-box routine-upgrade coverage checks both WAL and rollback journals and preserves users, settings and active central sessions.

Schema 22 adds checked JSON claim requirements to federation providers, defaulting existing rows to `[]`. The real-CLI upgrade regression covers WAL and rollback journals, preserves provider secrets and ordering without routine backups, and rejects malformed/non-array storage.
