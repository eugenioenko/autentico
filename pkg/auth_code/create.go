package authcode

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func CreateAuthCode(code AuthCode) error {
	query := `
		INSERT INTO auth_codes (
			code, user_id, client_id, redirect_uri, scope, nonce,
			code_challenge, code_challenge_method,
			expires_at, used, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err := db.GetDB().Exec(query,
		code.Code,
		code.UserID,
		code.ClientID,
		code.RedirectURI,
		code.Scope,
		code.Nonce,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.ExpiresAt,
		code.Used,
		code.CreatedAt,
	)

	return err
}
