package migrations

import (
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRoutineUpgradeValidatesEncryptedEnrollmentsBeforeSQL(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "wrong key", true: "corrupt ciphertext"}[corrupt], func(t *testing.T) {
			database := newTestDB(t)
			plan := migrations
			useTestMigrations(t, plan[:18])
			require.NoError(t, Run(database, false))
			originalKey := config.Bootstrap.TotpEncryptionKey
			t.Cleanup(func() { config.Bootstrap.TotpEncryptionKey = originalKey })
			stored, err := totpsecret.Seal(originalKey, "u", "SEED")
			require.NoError(t, err)
			if corrupt {
				stored = totpsecret.Prefix + "invalid"
			} else {
				config.Bootstrap.TotpEncryptionKey, err = totpsecret.GenerateKey()
				require.NoError(t, err)
			}
			_, err = database.Exec(`INSERT INTO users(id,username,totp_secret,totp_verified) VALUES('u','u',?,TRUE)`, stored)
			require.NoError(t, err)
			migrations, SchemaVersion = plan, len(plan)
			require.Error(t, Run(database, false))
			version, err := getUserVersion(database)
			require.NoError(t, err)
			require.Equal(t, 18, version)
			var actual string
			require.NoError(t, database.QueryRow(`SELECT totp_secret FROM users WHERE id='u'`).Scan(&actual))
			require.Equal(t, stored, actual)
		})
	}
}
