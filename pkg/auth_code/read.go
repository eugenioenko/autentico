package authcode

import (
	"autentico/pkg/db"
	"database/sql"
	"errors"
)

func AuthCodeByCode(code string) (*AuthCode, error) {
	query := `
        SELECT code, user_id, redirect_uri, scope, expires_at, used, created_at
        FROM auth_codes
        WHERE code = ?;
    `
	row := db.GetDB().QueryRow(query, code)

	var authCode AuthCode
	err := row.Scan(
		&authCode.Code,
		&authCode.UserID,
		&authCode.RedirectURI,
		&authCode.Scope,
		&authCode.ExpiresAt,
		&authCode.Used,
		&authCode.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No record found
		}
		return nil, err // Other errors
	}

	return &authCode, nil
}
