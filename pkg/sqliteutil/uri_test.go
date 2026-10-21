package sqliteutil

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileURL(t *testing.T) {
	for _, path := range []string{"/data/identity #é?%.db", "C:/data/identity #é?%.db", "//server/share/identity.db"} {
		t.Run(path, func(t *testing.T) {
			u := FileURL(path)
			require.Empty(t, u.Host)
			want := path
			if path[0] == 'C' {
				want = "/" + path
			}
			require.Equal(t, want, u.Path)
			require.Empty(t, u.RawQuery)
			require.Empty(t, u.Fragment)
			require.Contains(t, u.String(), "file:///")
		})
	}
	// Uses native separators, including backslashes on the Windows CI runner.
	u := FileURL(filepath.Join(t.TempDir(), "identity #é.db"))
	require.Empty(t, u.Host)
	require.NotContains(t, u.String(), "%5C")
	memory := FileURL(":memory:")
	require.Equal(t, "file::memory:", memory.String())
}
