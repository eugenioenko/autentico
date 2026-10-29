package migrationstest

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRoutineForwardAuthUpgradePreservesExistingCredentials(t *testing.T) {
	for _, journal := range []string{"WAL", "DELETE"} {
		t.Run(journal, func(t *testing.T) {
			path, database := fixture(t, 20, journal, false)
			_, err := database.Exec(`INSERT INTO users(id,username,password) VALUES('fa-user','fa-user','original-hash');
                INSERT INTO idp_sessions(id,user_id) VALUES('fa-parent','fa-user');
                INSERT INTO settings(key,value) VALUES('kept-setting','original-value')`)
			require.NoError(t, err)
			require.NoError(t, database.Close())
			text, err := command(t, path, fmt.Sprintf("%d\n", target), "migrate")
			require.NoError(t, err, text)
			require.Equal(t, target, schema(t, path))
			upgraded := openDB(t, path)
			var password, setting string
			require.NoError(t, upgraded.QueryRow(`SELECT password FROM users WHERE id='fa-user'`).Scan(&password))
			require.Equal(t, "original-hash", password)
			require.NoError(t, upgraded.QueryRow(`SELECT value FROM settings WHERE key='kept-setting'`).Scan(&setting))
			require.Equal(t, "original-value", setting)
			var n int
			require.NoError(t, upgraded.QueryRow(`SELECT COUNT(*) FROM idp_sessions WHERE id='fa-parent' AND deactivated_at IS NULL`).Scan(&n))
			require.Equal(t, 1, n)
			for _, table := range []string{"protected_apps", "forward_auth_sessions"} {
				require.NoError(t, upgraded.QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&n))
				require.Zero(t, n)
			}
			require.Empty(t, backups(t, path))
		})
	}
}
