package migrations

import (
	"os"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	key, err := totpsecret.GenerateKey()
	if err != nil {
		panic(err)
	}
	config.Bootstrap.TotpEncryptionKey = key
	os.Exit(m.Run())
}

func TestEncryptTotpPreservesEnrollmentState(t *testing.T) {
	database := newTestDB(t)
	plan := migrations
	useTestMigrations(t, plan[:16])
	require.NoError(t, Run(database, false))
	_, err := database.Exec(`INSERT INTO users(id,username,totp_secret,totp_verified,totp_last_used_step,totp_failed_attempts)
		VALUES ('enrolled','enrolled','JBSWY3DPEHPK3PXP',TRUE,42,3),
		('pending','pending','PENDING-SEED',FALSE,-1,0),('empty','empty','',FALSE,-1,0)`)
	require.NoError(t, err)
	lockedUntil := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	_, err = database.Exec(`UPDATE users SET totp_locked_until=? WHERE id='enrolled'`, lockedUntil)
	require.NoError(t, err)
	migrations, SchemaVersion = plan, 17
	require.NoError(t, Run(database, false))
	var stored string
	var verified bool
	var step int64
	var attempts int
	var actualLock time.Time
	require.NoError(t, database.QueryRow(`SELECT totp_secret,totp_verified,totp_last_used_step,totp_failed_attempts,totp_locked_until FROM users WHERE id='enrolled'`).Scan(&stored, &verified, &step, &attempts, &actualLock))
	plain, err := totpsecret.Open(config.GetBootstrap().TotpEncryptionKey, "enrolled", stored)
	require.NoError(t, err)
	require.Equal(t, "JBSWY3DPEHPK3PXP", plain)
	require.True(t, verified)
	require.EqualValues(t, 42, step)
	require.Equal(t, 3, attempts)
	require.True(t, lockedUntil.Equal(actualLock))
	require.NoError(t, database.QueryRow(`SELECT totp_secret,totp_verified FROM users WHERE id='pending'`).Scan(&stored, &verified))
	plain, err = totpsecret.Open(config.GetBootstrap().TotpEncryptionKey, "pending", stored)
	require.NoError(t, err)
	require.Equal(t, "PENDING-SEED", plain)
	require.False(t, verified)
	require.NoError(t, database.QueryRow(`SELECT totp_secret FROM users WHERE id='empty'`).Scan(&stored))
	require.Empty(t, stored)
}
