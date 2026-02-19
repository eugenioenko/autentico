package trusteddevice

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateLastUsed(id string) error {
	_, err := db.GetDB().Exec(
		`UPDATE trusted_devices SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, id,
	)
	return err
}
