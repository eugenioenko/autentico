package authcode

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func CreateAuthCode(code AuthCode) error {
	if code.CreatedAt.IsZero() {
		code.CreatedAt = time.Now().UTC()
	}
	query := `
		INSERT INTO auth_codes (
			code, user_id, client_id, redirect_uri, scope, nonce,
			code_challenge, code_challenge_method,
			expires_at, used, created_at, idp_session_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	// idp_session_id is nullable: empty string -> SQL NULL so non-browser grants
	// (ROPC, client_credentials — none of which call CreateAuthCode today) and
	// legacy rows never populated by /authorize stay out of cascade queries.
	var idpSession interface{}
	if code.IdpSessionID != "" {
		idpSession = code.IdpSessionID
	}
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
		idpSession,
	)

	return err
}
