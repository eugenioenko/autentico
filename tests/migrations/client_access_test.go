package migrationstest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoutineClientAccessUpgrade(t *testing.T) {
	for _, journal := range []string{"WAL", "DELETE"} {
		t.Run(journal, func(t *testing.T) {
			path, database := fixture(t, 23, journal, false)
			_, err := database.Exec(`INSERT INTO clients(id,client_id,client_name,redirect_uris) VALUES('c','existing','Existing','["https://app.example/cb"]');
				INSERT INTO users(id,username,password) VALUES('user','user','hash');
				INSERT INTO groups(id,name) VALUES('group','staff')`)
			require.NoError(t, err)
			require.NoError(t, database.Close())
			output, err := command(t, path, fmt.Sprintf("%d\n", target), "migrate")
			require.NoError(t, err, output)
			require.Equal(t, target, schema(t, path))
			require.Empty(t, backups(t, path), "a routine upgrade takes no backup")

			upgraded := openDB(t, path)
			var restrict bool
			require.NoError(t, upgraded.QueryRow(`SELECT restrict_access FROM clients WHERE client_id='existing'`).Scan(&restrict))
			require.False(t, restrict, "existing clients stay open to every user")

			_, err = upgraded.Exec(`INSERT INTO client_allowed_groups(client_id,group_id) VALUES('existing','missing')`)
			require.Error(t, err)
			_, err = upgraded.Exec(`INSERT INTO client_allowed_users(client_id,user_id) VALUES('missing','user')`)
			require.Error(t, err)
			_, err = upgraded.Exec(`INSERT INTO client_allowed_groups(client_id,group_id) VALUES('existing','group');
				INSERT INTO client_allowed_users(client_id,user_id) VALUES('existing','user')`)
			require.NoError(t, err)
			_, err = upgraded.Exec(`DELETE FROM groups WHERE id='group'; DELETE FROM users WHERE id='user'`)
			require.NoError(t, err)
			var count int
			require.NoError(t, upgraded.QueryRow(`SELECT (SELECT COUNT(*) FROM client_allowed_groups)+(SELECT COUNT(*) FROM client_allowed_users)`).Scan(&count))
			require.Zero(t, count)
		})
	}
}
