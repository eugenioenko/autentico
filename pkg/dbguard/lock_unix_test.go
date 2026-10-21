//go:build !windows

package dbguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLockRejectsLinkedFiles(t *testing.T) {
	for _, symbolic := range []bool{true, false} {
		t.Run(map[bool]string{true: "symlink", false: "hardlink"}[symbolic], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.db")
			target := path + ".unrelated"
			require.NoError(t, os.WriteFile(target, []byte("unchanged"), 0600))
			if symbolic {
				require.NoError(t, os.Symlink(target, path+".lock"))
			} else {
				require.NoError(t, os.Link(target, path+".lock"))
			}
			_, err := Acquire(path, true)
			require.Error(t, err)
			contents, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Equal(t, "unchanged", string(contents))
		})
	}
}
