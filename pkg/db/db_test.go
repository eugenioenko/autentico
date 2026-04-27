package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eugenioenko/autentico/pkg/db/migrations"
)

func TestInitDB(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test.db")
	assert.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	database, err := InitDB(tmpFile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, database)

	err = database.Ping()
	assert.NoError(t, err)

	CloseDB()
}

func TestInitDB_StampsUserVersion(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test.db")
	assert.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	database, err := InitDB(tmpFile.Name())
	assert.NoError(t, err)

	var v int
	err = database.QueryRow("PRAGMA user_version").Scan(&v)
	assert.NoError(t, err)
	assert.Equal(t, migrations.SchemaVersion, v)

	CloseDB()
}

func TestInitDB_DoesNotResetUserVersion(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test.db")
	assert.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// First init stamps v1
	database, err := InitDB(tmpFile.Name())
	assert.NoError(t, err)

	// Simulate a migration having been applied (v2)
	_, err = database.Exec("PRAGMA user_version = 2")
	assert.NoError(t, err)
	CloseDB()

	// Re-open — should not reset user_version back to 1
	database, err = InitDB(tmpFile.Name())
	assert.NoError(t, err)

	var v int
	err = database.QueryRow("PRAGMA user_version").Scan(&v)
	assert.NoError(t, err)
	assert.Equal(t, 2, v)

	CloseDB()
}

func TestInitTestDB(t *testing.T) {
	database, err := InitTestDB()
	assert.NoError(t, err)
	assert.NotNil(t, database)

	err = database.Ping()
	assert.NoError(t, err)

	// Check if GetWriteDB returns the same underlying writer
	assert.Equal(t, database, GetWriteDB())

	var v int
	err = database.QueryRow("PRAGMA user_version").Scan(&v)
	assert.NoError(t, err)
	assert.Equal(t, migrations.SchemaVersion, v)

	CloseDB()
}

func TestInitDB_InvalidPath(t *testing.T) {
	_, err := InitDB("/nonexistent/path/to/db.sqlite")
	assert.Error(t, err)
}

func TestCloseDB_Success(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "testdb*.sqlite")
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	_, err := InitDB(tmpPath)
	assert.NoError(t, err)

	CloseDB()

	// Calling CloseDB again should be fine (idempotent)
	CloseDB()
}

func TestInitTestDB_Success(t *testing.T) {
	db, _ := InitTestDB()
	assert.NotNil(t, db)

	// Verify tables are created (simple check)
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&name)
	assert.NoError(t, err)
	assert.Equal(t, "users", name)
}

func TestInitDB_ExistingDir(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "testdb-dir")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a subdirectory with the same name as the intended DB file
	dbPath := tmpDir + "/mydb.sqlite"
	_ = os.Mkdir(dbPath, 0755)

	// InitDB should fail because it can't open a directory as a DB
	_, err := InitDB(dbPath)
	assert.Error(t, err)
}
