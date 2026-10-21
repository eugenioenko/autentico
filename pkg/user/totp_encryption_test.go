package user

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestTotpStorageEncryptsAndPreservesReplayState(t *testing.T) {
	testutils.WithTestDB(t)
	usr, err := CreateUser("encrypted-user", "password123", "encrypted@example.com")
	require.NoError(t, err)
	const seed = "JBSWY3DPEHPK3PXP"
	require.NoError(t, StoreTotpSecretPending(usr.ID, seed))
	var stored string
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_secret FROM users WHERE id=?`, usr.ID).Scan(&stored))
	require.NotEqual(t, seed, stored)
	require.Contains(t, stored, totpsecret.Prefix)
	current, err := UserByID(usr.ID)
	require.NoError(t, err)
	require.Equal(t, seed, current.TotpSecret)
	// A second setup page must return the existing seed, rather than replace it.
	actual, err := EnsurePendingTotpSecret(usr.ID, "different-secret")
	require.NoError(t, err)
	require.Equal(t, seed, actual)
	require.NoError(t, SaveTotpSecret(usr.ID, seed))
	_, err = db.GetDB().Exec(`UPDATE users SET totp_last_used_step=123 WHERE id=?`, usr.ID)
	require.NoError(t, err)
	require.NoError(t, SaveTotpSecret(usr.ID, seed))
	var step int64
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_secret,totp_last_used_step FROM users WHERE id=?`, usr.ID).Scan(&stored, &step))
	require.EqualValues(t, 123, step)
	current, err = AuthenticateUser("encrypted-user", "password123")
	require.NoError(t, err)
	require.Equal(t, seed, current.TotpSecret)
	require.NoError(t, ValidateTotpEncryption())
	require.NoError(t, SaveTotpSecret(usr.ID, "different-secret"))
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_last_used_step FROM users WHERE id=?`, usr.ID).Scan(&step))
	require.EqualValues(t, -1, step)
}

func TestTotpStorageRejectsWrongKeyAndPlaintext(t *testing.T) {
	testutils.WithTestDB(t)
	usr, err := CreateUser("encrypted-user", "password123", "encrypted@example.com")
	require.NoError(t, err)
	require.NoError(t, SaveTotpSecret(usr.ID, "JBSWY3DPEHPK3PXP"))
	correctKey := config.GetBootstrap().TotpEncryptionKey
	wrongKey, err := totpsecret.GenerateKey()
	require.NoError(t, err)
	config.Bootstrap.TotpEncryptionKey = wrongKey
	_, err = UserByID(usr.ID)
	require.Error(t, err)
	require.Error(t, ValidateTotpEncryption())
	_, err = AuthenticateUser("encrypted-user", "password123")
	require.Error(t, err)
	config.Bootstrap.TotpEncryptionKey = correctKey
	_, err = db.GetDB().Exec(`UPDATE users SET totp_secret='plaintext' WHERE id=?`, usr.ID)
	require.NoError(t, err)
	_, err = UserByID(usr.ID)
	require.ErrorContains(t, err, "not encrypted")
	require.Error(t, ValidateTotpEncryption())
}
