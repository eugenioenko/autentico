package token

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// RevokeTokensByUserAndClient sets revoked_at on all non-revoked authorization_code
// grant tokens for the given user. Called when auth code reuse is detected per RFC 6749 §4.1.2.
// clientID is accepted for logging context but the tokens table has no client_id column.
func RevokeTokensByUserAndClient(userID, _ string) error {
	_, err := db.GetWriteDB().Exec(`
		UPDATE tokens
		SET revoked_at = ?
		WHERE user_id = ? AND grant_type = 'authorization_code' AND revoked_at IS NULL
	`, time.Now().UTC(), userID)
	return err
}

// RevokeByID sets revoked_at on a single token row by its primary key.
// Returns an error if the row doesn't exist or is already revoked.
func RevokeByID(id string) error {
	res, err := db.GetWriteDB().Exec(`
		UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
	`, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found or already revoked")
	}
	return nil
}

// RevokeByTokenValue sets revoked_at on any tokens row whose access_token or
// refresh_token matches the given value. Used by /oauth2/revoke (RFC 7009) —
// per §2.2 revoking a refresh token SHOULD also invalidate its access token,
// and our schema stores both on the same row, so one UPDATE does both.
// A no-op if the token is not found, per §2.2 ("respond with 200 whether the
// token is valid, invalid, or unknown").
func RevokeByTokenValue(tokenValue string) error {
	_, err := db.GetWriteDB().Exec(`
		UPDATE tokens
		SET revoked_at = ?
		WHERE access_token = ? OR refresh_token = ?
	`, time.Now().UTC(), tokenValue, tokenValue)
	return err
}
