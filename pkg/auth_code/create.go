package authcode

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// CreateAuthCode stores a new grant, recording an explicit effective PKCE
// method so historical unlabelled S256 codes keep their distinct binding.
func CreateAuthCode(code AuthCode) error {
	if code.CreatedAt.IsZero() {
		code.CreatedAt = time.Now().UTC()
	}
	// RFC 7636 §4.3 / §4.4: every newly issued PKCE code stores an
	// explicit method, including signed flows that bypass /authorize.
	// Empty stored methods are reserved for pre-fix S256 bindings.
	if code.CodeChallenge != "" && code.CodeChallengeMethod == "" {
		code.CodeChallengeMethod = "plain"
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
