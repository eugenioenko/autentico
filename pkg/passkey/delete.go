package passkey

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func DeletePasskeyCredential(credentialID string) error {
	_, err := db.GetDB().Exec(`DELETE FROM passkey_credentials WHERE id = ?`, credentialID)
	return err
}
