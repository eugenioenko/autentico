package user

import (
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
)

func decryptTotpSecret(userID, stored string) (string, error) {
	return totpsecret.Open(config.GetBootstrap().TotpEncryptionKey, userID, stored)
}

func encryptTotpSecret(userID, secret string) (string, error) {
	return totpsecret.Seal(config.GetBootstrap().TotpEncryptionKey, userID, secret)
}

// ValidateTotpEncryption checks every enrollment before the service accepts
// traffic. A wrong key or corrupt row never silently disables a second factor.
func ValidateTotpEncryption() error {
	if err := totpsecret.ValidateKey(config.GetBootstrap().TotpEncryptionKey); err != nil {
		return err
	}
	rows, err := db.GetDB().Query(`SELECT id, totp_secret FROM users WHERE totp_secret <> ''`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, stored string
		if err := rows.Scan(&id, &stored); err != nil {
			return err
		}
		if _, err := decryptTotpSecret(id, stored); err != nil {
			return err
		}
	}
	return rows.Err()
}
