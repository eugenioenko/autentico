package migrationstest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoutineGroupClaimsUpgrade(t *testing.T) {
	for _, journal := range []string{"WAL", "DELETE"} {
		t.Run(journal, func(t *testing.T) {
			path, database := fixture(t, 22, journal, false)
			_, err := database.Exec(`INSERT INTO users(id,username,password) VALUES('user','user','hash');
				INSERT INTO groups(id,name) VALUES('group','app1');
				INSERT INTO user_groups(user_id,group_id) VALUES('user','group');
				INSERT INTO user_claims(user_id,claim_name,claim_value) VALUES('user','tier','gold')`)
			require.NoError(t, err)
			require.NoError(t, database.Close())
			output, err := command(t, path, fmt.Sprintf("%d\n", target), "migrate")
			require.NoError(t, err, output)
			require.Equal(t, target, schema(t, path))
			require.Empty(t, backups(t, path))
			upgraded := openDB(t, path)
			var value string
			require.NoError(t, upgraded.QueryRow(`SELECT claim_value FROM user_claims WHERE user_id='user' AND claim_name='tier'`).Scan(&value))
			require.Equal(t, "gold", value)
			var memberCount int
			require.NoError(t, upgraded.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE user_id='user' AND group_id='group'`).Scan(&memberCount))
			require.Equal(t, 1, memberCount)
			_, err = upgraded.Exec(`INSERT INTO group_claims(group_id,claim_name,claim_value) VALUES('missing','role','user')`)
			require.Error(t, err)
			_, err = upgraded.Exec(`INSERT INTO group_claims(group_id,claim_name,claim_value) VALUES('group','role','user')`)
			require.NoError(t, err)
			_, err = upgraded.Exec(`DELETE FROM groups WHERE id='group'`)
			require.NoError(t, err)
			var count int
			require.NoError(t, upgraded.QueryRow(`SELECT COUNT(*) FROM group_claims`).Scan(&count))
			require.Zero(t, count)
		})
	}
}
