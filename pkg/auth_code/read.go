package authcode

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func AuthCodeByCode(code string) (*AuthCode, error) {
	query := `
        SELECT code, user_id, redirect_uri, scope, expires_at, used, created_at
        FROM auth_codes
        WHERE code = ?;
    `
	var authCode AuthCode
	err := db.GetDB().QueryRow(query, code).Scan(
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
			return nil, fmt.Errorf("authorization code not found")
		}
		return nil, err // Other errors
	}

	return &authCode, nil
}
