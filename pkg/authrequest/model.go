package authrequest

import "time"

// AuthorizeRequest stores the OAuth2 authorization parameters server-side
// between the authorize and login steps. This prevents parameter tampering
// via hidden form fields (PKCE downgrade, scope escalation, nonce injection).
type AuthorizeRequest struct {
	ID                  string    `db:"id"`
	ClientID            string    `db:"client_id"`
	RedirectURI         string    `db:"redirect_uri"`
	Scope               string    `db:"scope"`
	State               string    `db:"state"`
	Nonce               string    `db:"nonce"`
	CodeChallenge       string    `db:"code_challenge"`
	CodeChallengeMethod string    `db:"code_challenge_method"`
	ResponseType        string    `db:"response_type"`
	CreatedAt           time.Time `db:"created_at"`
	ExpiresAt           time.Time `db:"expires_at"`
}
