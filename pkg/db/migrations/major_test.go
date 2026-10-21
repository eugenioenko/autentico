package migrations

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func withPlan(t *testing.T, plan []Migration, target int) {
	t.Helper()
	original, version := migrations, SchemaVersion
	migrations, SchemaVersion = plan, target
	t.Cleanup(func() { migrations, SchemaVersion = original, version })
}

func TestRoutineMigrationsRemainAutomatic(t *testing.T) {
	database := newTestDB(t)
	_, err := database.Exec(`CREATE TABLE kept(value TEXT); INSERT INTO kept VALUES('preserved'); PRAGMA user_version=1`)
	require.NoError(t, err)
	withPlan(t, []Migration{{Version: 2, SQL: `CREATE TABLE routine(id TEXT)`}}, 2)
	require.NoError(t, CheckAuto(database))
	require.NoError(t, Run(database, false))
	version, err := getUserVersion(database)
	require.NoError(t, err)
	require.Equal(t, 2, version)
	var value string
	require.NoError(t, database.QueryRow("SELECT value FROM kept").Scan(&value))
	require.Equal(t, "preserved", value)
}

func TestMajorGatePrecedesRoutineMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	database, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = database.Close() }()
	_, err = database.Exec(`CREATE TABLE kept(value TEXT); INSERT INTO kept VALUES('preserved'); PRAGMA user_version=1`)
	require.NoError(t, err)
	withPlan(t, []Migration{{Version: 2, SQL: `CREATE TABLE routine(id TEXT)`}, {Version: 3, Major: true, SQL: `DELETE FROM kept`}}, 3)
	require.ErrorContains(t, CheckAuto(database), "automatic upgrade is disabled")
	require.ErrorContains(t, Run(database, false), "offline backup")
	version, err := getUserVersion(database)
	require.NoError(t, err)
	require.Equal(t, 1, version)
	var count int
	require.NoError(t, database.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='routine'").Scan(&count))
	require.Zero(t, count)
}

func TestEveryPendingMajorRequiresApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	database, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = database.Exec(`CREATE TABLE kept(value TEXT); INSERT INTO kept VALUES('preserved'); PRAGMA user_version=1`)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	withPlan(t, []Migration{{Version: 2, Major: true, SQL: `DELETE FROM kept`}, {Version: 3, Major: true, SQL: `CREATE TABLE final(id TEXT)`}}, 3)
	require.ErrorContains(t, RunFile(path, false, 2), "--approve-major=3")
	files, err := filepath.Glob(path + ".pre-v3-*.db")
	require.NoError(t, err)
	require.Empty(t, files)
	require.NoError(t, RunFile(path, false, 2, 3))
	files, err = filepath.Glob(path + ".pre-v3-*.db")
	require.NoError(t, err)
	require.Len(t, files, 1)
}
