package migrationstest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// The helper sets a real kernel file-size limit before execing the application.
// It exercises real write failures, including when the tests run as root.
func TestMigrationFileLimitHelper(t *testing.T) {
	if os.Getenv("AUTENTICO_TEST_LIMIT_HELPER") != "1" {
		return
	}
	limit := uint64(4096)
	if configured := os.Getenv("AUTENTICO_TEST_FILE_LIMIT"); configured != "" {
		var err error
		limit, err = strconv.ParseUint(configured, 10, 64)
		require.NoError(t, err)
	}
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: limit, Max: limit}))
	app := os.Getenv("AUTENTICO_TEST_APP")
	require.NoError(t, syscall.Exec(app, []string{app, "migrate", "--approve-major=15,17"}, os.Environ()))
}

func TestTotpRebuildWriteFailureRestoresCommittedEncryptionAndCanRetry(t *testing.T) {
	path, database := fixture(t, 16, "WAL", false)
	_, err := database.Exec(`INSERT INTO users(id,username,totp_secret,totp_verified)
		VALUES('u','u','ORIGINAL-SEED',TRUE);
		INSERT INTO settings(key,value) VALUES('vacuum-padding',hex(zeroblob(262144)))`)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	before := digest(t, path)
	info, err := os.Stat(path)
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMigrationFileLimitHelper$")
	cmd.Dir = filepath.Dir(path)
	// The snapshot fits, as do the small encryption writes. Rebuilding every
	// page exceeds this limit in WAL because its page frames add overhead.
	cmd.Env = append(env(path), "AUTENTICO_TEST_LIMIT_HELPER=1", "AUTENTICO_TEST_APP="+binary,
		"AUTENTICO_TEST_FILE_LIMIT="+strconv.FormatInt(info.Size(), 10))
	output, err := cmd.CombinedOutput()
	require.Error(t, err, string(output))
	require.Contains(t, string(output), "remove historical plaintext after TOTP encryption")
	require.Contains(t, string(output), "restored schema v16")
	require.Equal(t, before, digest(t, path))
	require.Equal(t, 16, schema(t, path))
	noRecovery(t, path)
	database = openDB(t, path)
	var seed string
	require.NoError(t, database.QueryRow(`SELECT totp_secret FROM users WHERE id='u'`).Scan(&seed))
	require.Equal(t, "ORIGINAL-SEED", seed)
	require.NoError(t, database.Close())
	text, err := command(t, path, "", "migrate", "--approve-major=17")
	require.NoError(t, err, text)
	require.Equal(t, target, schema(t, path))
}

func TestPartialBackupWriteFailsBeforeMigration(t *testing.T) {
	path, db := fixture(t, 14, "DELETE", true)
	require.NoError(t, db.Close())
	before := digest(t, path)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMigrationFileLimitHelper$")
	cmd.Dir = filepath.Dir(path)
	cmd.Env = append(env(path), "AUTENTICO_TEST_LIMIT_HELPER=1", "AUTENTICO_TEST_APP="+binary)
	output, err := cmd.CombinedOutput()
	require.Error(t, err, string(output))
	require.Contains(t, string(output), "major migration backup failed")
	require.Equal(t, before, digest(t, path))
	require.Equal(t, 14, schema(t, path))
	require.Empty(t, backups(t, path))
	noRecovery(t, path)
}
