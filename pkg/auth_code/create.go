package authcode

import (
	"autentico/pkg/db"
)

func CreateAuthCode(code AuthCode) error {
	query := `
		INSERT INTO auth_codes (
			code, user_id, redirect_uri, scope,
			expires_at, used, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?);
	`
	_, err := db.GetDB().Exec(query,
		code.Code,
		code.UserID,
		code.RedirectURI,
		code.Scope,
		code.ExpiresAt,
		code.Used,
		code.CreatedAt,
	)

	return err
}
