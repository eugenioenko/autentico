package token

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// RevokeTokensByUserAndClient sets revoked_at on all non-revoked authorization_code
// grant tokens for the given user. Called when auth code reuse is detected per RFC 6749 §4.1.2.
// clientID is accepted for logging context but the tokens table has no client_id column.
func RevokeTokensByUserAndClient(userID, _ string) error {
	_, err := db.GetDB().Exec(`
		UPDATE tokens
		SET revoked_at = ?
		WHERE user_id = ? AND grant_type = 'authorization_code' AND revoked_at IS NULL
	`, time.Now().UTC(), userID)
	return err
}

// RevokeByTokenValue sets revoked_at on any tokens row whose access_token or
// refresh_token matches the given value. Used by /oauth2/revoke (RFC 7009) —
// per §2.2 revoking a refresh token SHOULD also invalidate its access token,
// and our schema stores both on the same row, so one UPDATE does both.
// A no-op if the token is not found, per §2.2 ("respond with 200 whether the
// token is valid, invalid, or unknown").
func RevokeByTokenValue(tokenValue string) error {
	_, err := db.GetDB().Exec(`
		UPDATE tokens
		SET revoked_at = ?
		WHERE access_token = ? OR refresh_token = ?
	`, time.Now().UTC(), tokenValue, tokenValue)
	return err
}
