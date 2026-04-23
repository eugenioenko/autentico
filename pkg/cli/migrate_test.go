package cli

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
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

func TestMigrate_RunSucceeds(t *testing.T) {
	// WithTestDB already runs every migration, so we can't simply reset
	// user_version and replay — migrations that add columns (e.g. 006's
	// idp_session_id) are not idempotent on top of an already-current schema.
	// Call Run against an up-to-date DB and confirm it's a no-op.
	testutils.WithTestDB(t)

	err := migrations.Run(db.GetDB(), true)
	assert.NoError(t, err)

	err = migrations.Check(db.GetDB())
	assert.NoError(t, err)
}
