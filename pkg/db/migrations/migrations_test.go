package migrations

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func setUserVersion(t *testing.T, db *sql.DB, v int) {
	t.Helper()
	_, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", v))
	require.NoError(t, err)
}

func TestGetUserVersion(t *testing.T) {
	db := newTestDB(t)
	v, err := getUserVersion(db)
	assert.NoError(t, err)
	assert.Equal(t, 0, v)

	setUserVersion(t, db, 5)
	v, err = getUserVersion(db)
	assert.NoError(t, err)
	assert.Equal(t, 5, v)
}

func TestCheck_UpToDate(t *testing.T) {
	db := newTestDB(t)
	setUserVersion(t, db, SchemaVersion)
	assert.NoError(t, Check(db))
}

func TestCheck_Behind(t *testing.T) {
	db := newTestDB(t)
	setUserVersion(t, db, SchemaVersion-1)
	err := Check(db)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("version %d", SchemaVersion-1))
	assert.Contains(t, err.Error(), fmt.Sprintf("version %d", SchemaVersion))
	assert.Contains(t, err.Error(), "autentico migrate")
}

func TestRun_AlreadyUpToDate(t *testing.T) {
	db := newTestDB(t)
	setUserVersion(t, db, SchemaVersion)
	assert.NoError(t, Run(db, false))
	v, _ := getUserVersion(db)
	assert.Equal(t, SchemaVersion, v)
}

func TestRun_AppliesPendingMigrations(t *testing.T) {
	db := newTestDB(t)
	setUserVersion(t, db, 0)

	originalMigrations := migrations
	originalVersion := SchemaVersion
	t.Cleanup(func() {
		migrations = originalMigrations
		SchemaVersion = originalVersion
	})

	migrations = []Migration{
		{Version: 1, SQL: `CREATE TABLE migration_test_1 (id INTEGER PRIMARY KEY)`},
		{Version: 2, SQL: `CREATE TABLE migration_test_2 (id INTEGER PRIMARY KEY)`},
	}
	SchemaVersion = 2

	err := Run(db, false)
	require.NoError(t, err)

	v, _ := getUserVersion(db)
	assert.Equal(t, 2, v)

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='migration_test_1'").Scan(&name)
	assert.NoError(t, err)
	assert.Equal(t, "migration_test_1", name)

	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='migration_test_2'").Scan(&name)
	assert.NoError(t, err)
	assert.Equal(t, "migration_test_2", name)
}

func TestRun_SkipsAlreadyApplied(t *testing.T) {
	db := newTestDB(t)

	originalMigrations := migrations
	originalVersion := SchemaVersion
	t.Cleanup(func() {
		migrations = originalMigrations
		SchemaVersion = originalVersion
	})

	migrations = []Migration{
		{Version: 1, SQL: `CREATE TABLE migration_skip_1 (id INTEGER PRIMARY KEY)`},
		{Version: 2, SQL: `CREATE TABLE migration_skip_2 (id INTEGER PRIMARY KEY)`},
	}
	SchemaVersion = 2

	// Simulate version 1 already applied
	setUserVersion(t, db, 1)
	_, err := db.Exec(`CREATE TABLE migration_skip_1 (id INTEGER PRIMARY KEY)`)
	require.NoError(t, err)

	err = Run(db, false)
	require.NoError(t, err)

	v, _ := getUserVersion(db)
	assert.Equal(t, 2, v)

	// migration_skip_1 already existed — no error
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='migration_skip_2'").Scan(&name)
	assert.NoError(t, err)
	assert.Equal(t, "migration_skip_2", name)
}

func TestRun_BadSQLReturnsError(t *testing.T) {
	db := newTestDB(t)
	setUserVersion(t, db, 0)

	original := migrations
	t.Cleanup(func() { migrations = original })

	migrations = []Migration{
		{Version: 1, SQL: `THIS IS NOT VALID SQL !!!`},
	}

	err := Run(db, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "v1")

	// Version must not have advanced
	v, _ := getUserVersion(db)
	assert.Equal(t, 0, v)
}

func TestRun_Idempotent(t *testing.T) {
	db := newTestDB(t)
	setUserVersion(t, db, SchemaVersion)

	// Calling Run twice should be fine
	assert.NoError(t, Run(db, false))
	assert.NoError(t, Run(db, false))

	v, _ := getUserVersion(db)
	assert.Equal(t, SchemaVersion, v)
}

func useTestMigrations(t *testing.T, entries []Migration) {
	t.Helper()
	originalMigrations, originalVersion := migrations, SchemaVersion
	t.Cleanup(func() {
		migrations, SchemaVersion = originalMigrations, originalVersion
	})
	migrations = entries
	SchemaVersion = entries[len(entries)-1].Version
}

func TestRun_DataTransformations(t *testing.T) {
	db := newTestDB(t)
	var calls int
	useTestMigrations(t, []Migration{
		{
			Version: 1,
			SQL:     `CREATE TABLE secrets (value TEXT); INSERT INTO secrets VALUES ('plaintext')`,
			Func: func(tx *sql.Tx) error {
				// The schema and seed data must be visible before the callback runs.
				_, err := tx.Exec(`UPDATE secrets SET value = 'encrypted' WHERE value = 'plaintext'`)
				return err
			},
		},
		{
			Version: 2,
			Func: func(tx *sql.Tx) error {
				calls++
				_, err := tx.Exec(`INSERT INTO secrets VALUES ('callback-only')`)
				return err
			},
		},
	})

	require.NoError(t, Run(db, false))
	require.NoError(t, Run(db, false))
	assert.Equal(t, 1, calls, "applied callbacks must not run again")
	var transformed, callbackOnly int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE value = 'encrypted'`).Scan(&transformed))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE value = 'callback-only'`).Scan(&callbackOnly))
	assert.Equal(t, 1, transformed)
	assert.Equal(t, 1, callbackOnly)
	version, err := getUserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func TestRun_SQLFailureRollsBackOnlyFailingMigration(t *testing.T) {
	db := newTestDB(t)
	useTestMigrations(t, []Migration{
		{Version: 1, SQL: `CREATE TABLE values_to_migrate (value TEXT); INSERT INTO values_to_migrate VALUES ('original')`},
		{Version: 2, SQL: `UPDATE values_to_migrate SET value = 'partial'; CREATE TABLE partial_schema (id INTEGER); INVALID SQL`},
		{Version: 3, SQL: `CREATE TABLE must_not_run (id INTEGER)`},
	})

	err := Run(db, false)
	require.ErrorContains(t, err, "SQL for v2")
	var value string
	require.NoError(t, db.QueryRow(`SELECT value FROM values_to_migrate`).Scan(&value))
	assert.Equal(t, "original", value)
	var tables int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('partial_schema', 'must_not_run')`).Scan(&tables))
	assert.Zero(t, tables)
	version, err := getUserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 1, version, "earlier successful migrations must stay committed")
}

func TestRun_CallbackFailureRollsBackSchemaAndData(t *testing.T) {
	db := newTestDB(t)
	_, err := db.Exec(`CREATE TABLE existing_data (value TEXT); INSERT INTO existing_data VALUES ('original')`)
	require.NoError(t, err)
	failure := errors.New("transformation failed")
	useTestMigrations(t, []Migration{{
		Version: 1,
		SQL:     `CREATE TABLE new_schema (id INTEGER); UPDATE existing_data SET value = 'partial'`,
		Func: func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO existing_data VALUES ('callback-write')`); err != nil {
				return err
			}
			return failure
		},
	}})

	err = Run(db, false)
	require.ErrorIs(t, err, failure)
	assert.ErrorContains(t, err, "transform data for v1")
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM existing_data`).Scan(&count))
	assert.Equal(t, 1, count)
	var value string
	require.NoError(t, db.QueryRow(`SELECT value FROM existing_data`).Scan(&value))
	assert.Equal(t, "original", value)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'new_schema'`).Scan(&count))
	assert.Zero(t, count)
	version, err := getUserVersion(db)
	require.NoError(t, err)
	assert.Zero(t, version)
}

func TestRun_CommitFailureRollsBackVersion(t *testing.T) {
	db := newTestDB(t)
	_, err := db.Exec(`PRAGMA foreign_keys = ON`)
	require.NoError(t, err)
	useTestMigrations(t, []Migration{{
		Version: 1,
		SQL: `CREATE TABLE parent (id INTEGER PRIMARY KEY);
			CREATE TABLE child (parent_id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
			INSERT INTO child VALUES (123)`,
	}})

	err = Run(db, false)
	require.ErrorContains(t, err, "commit v1")
	version, err := getUserVersion(db)
	require.NoError(t, err)
	assert.Zero(t, version)
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('parent', 'child')`).Scan(&count))
	assert.Zero(t, count)

	// The pooled connection must also be usable for a corrected retry.
	migrations[0].SQL = `CREATE TABLE parent (id INTEGER PRIMARY KEY);
		CREATE TABLE child (parent_id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
		INSERT INTO parent VALUES (123); INSERT INTO child VALUES (123)`
	require.NoError(t, Run(db, false))
	version, err = getUserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 1, version)
}

// TestRun_MagicLinkAttemptsUpgrade preserves live tokens when upgrading a v12 database.
func TestRun_MagicLinkAttemptsUpgrade(t *testing.T) {
	db := newTestDB(t)
	allMigrations := migrations
	useTestMigrations(t, allMigrations[:12])
	require.NoError(t, Run(db, false))
	_, err := db.Exec(`INSERT INTO users (id, username) VALUES ('upgrade-user', 'upgrade-user');
		INSERT INTO magic_link_tokens (id, user_id, token_hash, code_hash, expires_at)
		VALUES ('upgrade-link', 'upgrade-user', 'existing-hash', 'existing-code', '2099-01-01 00:00:00')`)
	require.NoError(t, err)
	migrations, SchemaVersion = allMigrations[:13], 13
	require.NoError(t, Run(db, false))
	var hash, code string
	var attempts int
	require.NoError(t, db.QueryRow(`SELECT token_hash, code_hash, failed_attempts FROM magic_link_tokens WHERE id = 'upgrade-link'`).Scan(&hash, &code, &attempts))
	assert.Equal(t, "existing-hash", hash)
	assert.Equal(t, "existing-code", code)
	assert.Zero(t, attempts)
	version, err := getUserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 13, version)
}

// TestRun_TotpAttemptLimitsUpgrade preserves enrolled users when upgrading schema 13.
func TestRun_TotpAttemptLimitsUpgrade(t *testing.T) {
	db := newTestDB(t)
	allMigrations := migrations
	useTestMigrations(t, allMigrations[:13])
	require.NoError(t, Run(db, false))
	_, err := db.Exec(`INSERT INTO users (id, username, totp_secret, totp_verified)
		VALUES ('totp-upgrade', 'totp-upgrade', 'existing-seed', TRUE)`)
	require.NoError(t, err)
	migrations, SchemaVersion = allMigrations[:14], 14
	require.NoError(t, Run(db, false))
	var secret string
	var verified bool
	var attempts int
	var lockedUntil *time.Time
	require.NoError(t, db.QueryRow(`SELECT totp_secret, totp_verified, totp_failed_attempts, totp_locked_until
		FROM users WHERE id = 'totp-upgrade'`).Scan(&secret, &verified, &attempts, &lockedUntil))
	assert.Equal(t, "existing-seed", secret)
	assert.True(t, verified)
	assert.Zero(t, attempts)
	assert.Nil(t, lockedUntil)
}
