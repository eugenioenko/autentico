package migrations

import (
	"database/sql"
	"fmt"
	"testing"

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
	assert.Contains(t, err.Error(), "--auto-migrate")
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
