package migrationstest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoutineClaimRequirementsUpgradePreservesProvider(t *testing.T) {
	for _, journal := range []string{"WAL", "DELETE"} {
		t.Run(journal, func(t *testing.T) {
			path, database := fixture(t, 21, journal, false)
			_, err := database.Exec(`INSERT INTO federation_providers(id,name,issuer,client_id,client_secret,enabled,sort_order) VALUES('provider','Kept','https://issuer.example','client','kept-secret',1,7)`)
			require.NoError(t, err)
			require.NoError(t, database.Close())
			output, err := command(t, path, fmt.Sprintf("%d\n", target), "migrate")
			require.NoError(t, err, output)
			upgraded := openDB(t, path)
			var rules, secret string
			var order int
			require.NoError(t, upgraded.QueryRow(`SELECT claim_requirements,client_secret,sort_order FROM federation_providers WHERE id='provider'`).Scan(&rules, &secret, &order))
			require.Equal(t, "[]", rules)
			require.Equal(t, "kept-secret", secret)
			require.Equal(t, 7, order)
			require.Empty(t, backups(t, path))
			for _, bad := range []string{`null`, `{}`, `broken`} {
				_, err = upgraded.Exec(`UPDATE federation_providers SET claim_requirements=? WHERE id='provider'`, bad)
				require.Error(t, err)
			}
		})
	}
}
