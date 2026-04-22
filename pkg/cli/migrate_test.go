package cli

import (
	"database/sql"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"

	_ "modernc.org/sqlite"
)

func TestMigrate_AlreadyUpToDate(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.DbFilePath = ":memory:"
	})

	// After WithTestDB, schema is current — Check should pass
	err := migrations.Check(db.GetDB())
	assert.NoError(t, err)
}

func TestMigrate_CheckFailsOnOldSchema(t *testing.T) {
	testutils.WithTestDB(t)

	// Manually set user_version to 0 to simulate old schema
	_, err := db.GetDB().Exec("PRAGMA user_version = 0")
	assert.NoError(t, err)

	err = migrations.Check(db.GetDB())
	assert.Error(t, err)
}

// TestMigrate_RunSucceeds exercises the real-world path: a fresh database
// at user_version=0 is brought fully up to the current SchemaVersion by
// running all migrations in order.
//
// We can't use WithTestDB as the fixture — it already runs migrations and
// leaves the schema at HEAD. Re-running migrations on an already-migrated
// schema is not a supported scenario (e.g. ALTER TABLE ADD COLUMN is not
// idempotent in SQLite). Instead open a bare in-memory DB here.
func TestMigrate_RunSucceeds(t *testing.T) {
	fresh, err := sql.Open("sqlite", ":memory:")
	assert.NoError(t, err)
	defer func() { _ = fresh.Close() }()
	fresh.SetMaxOpenConns(1)

	// Confirm the starting state: a brand-new DB sits at user_version=0.
	var v int
	err = fresh.QueryRow("PRAGMA user_version").Scan(&v)
	assert.NoError(t, err)
	assert.Equal(t, 0, v)

	err = migrations.Run(fresh, true)
	assert.NoError(t, err)

	// Check should pass against the same DB we just migrated.
	err = migrations.Check(fresh)
	assert.NoError(t, err)
}
