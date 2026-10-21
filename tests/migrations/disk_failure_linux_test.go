package migrationstest

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// The helper sets a real kernel file-size limit before execing the application.
// It exercises a partial backup write, including when the tests run as root.
func TestMigrationFileLimitHelper(t *testing.T) {
	if os.Getenv("AUTENTICO_TEST_LIMIT_HELPER") != "1" {
		return
	}
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 4096, Max: 4096}))
	app := os.Getenv("AUTENTICO_TEST_APP")
	require.NoError(t, syscall.Exec(app, []string{app, "migrate", "--approve-major=15"}, os.Environ()))
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
