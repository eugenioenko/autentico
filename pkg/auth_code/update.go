package authcode

import (
	"autentico/pkg/db"
)

func MarkAuthCodeAsUsed(code string) error {
	query := `
		UPDATE auth_codes
		SET used = TRUE
		WHERE code = ?;
	`
	_, err := db.GetDB().Exec(query, code)
	return err
}
