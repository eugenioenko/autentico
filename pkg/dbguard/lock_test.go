package dbguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSharedAndExclusiveLocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	first, err := Acquire(path, false)
	require.NoError(t, err)
	second, err := Acquire(path, false)
	require.NoError(t, err)
	_, err = Acquire(path, true)
	require.Error(t, err)
	require.NoError(t, second.Close())
	require.NoError(t, first.Close())
	before, err := os.Stat(path + ".lock")
	require.NoError(t, err)
	exclusive, err := Acquire(path, true)
	require.NoError(t, err)
	_, err = Acquire(path, false)
	require.Error(t, err)
	require.NoError(t, exclusive.Close())
	after, err := os.Stat(path + ".lock")
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after), "lock inode must remain stable")
}
