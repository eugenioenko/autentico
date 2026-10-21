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
survive; old tokens, OAuth/SSO sessions, and pending login grants must not.

CI runs the real database and CLI migration suite on both Linux and Windows,
including paths containing spaces, Unicode, and URI-reserved characters.

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
application image. It checks startup refusal, headless approval, automatic
restoration after an injected failure, preserved host ownership, successful
retry, startup under the service UID after a root-run migration, and idempotent
deployment-job retry. The test
creates its own temporary data and Compose project and cleans them up afterward.
An existing compatible runtime image can be supplied with `--runtime-image`.
