package token

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// RevokeTokensByUserAndClient revokes code/refresh tokens for a legacy grant
// without a browser-session lineage (RFC 6749 §4.1.2).
func RevokeTokensByUserAndClient(userID, clientID string) error {
	return revokeAuthorizationGrant(userID, clientID, "")
}

// revokeAuthorizationGrant follows the existing IdP-session linkage across
// refresh rotation. Legacy codes without that linkage use a conservative
// user/client fallback, preserving independent password grants and other clients.
func revokeAuthorizationGrant(userID, clientID, idpSessionID string) error {
	_, err := db.GetDB().Exec(`UPDATE tokens SET revoked_at = ?
		WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL AND (
			(? <> '' AND access_token_hash IN (
				SELECT access_token_hash FROM sessions WHERE idp_session_id = ?))
			OR (? = '' AND grant_type IN ('authorization_code', 'refresh_token'))
		)`, time.Now().UTC(), userID, clientID, idpSessionID, idpSessionID, idpSessionID)
	return err
}

// RevokeByID sets revoked_at on a single token row by its primary key.
// Returns an error if the row doesn't exist or is already revoked.
func RevokeByID(id string) error {
	res, err := db.GetDB().Exec(`
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
	if tokenValue == "" {
		return nil
	}
	hash := utils.HashToken(tokenValue)
	_, err := db.GetDB().Exec(`
		UPDATE tokens
		SET revoked_at = ?
		WHERE access_token_hash = ? OR refresh_token_hash = ?
	`, time.Now().UTC(), hash, hash)
	return err
}

// revokeRefreshFamily retains the existing account-wide refresh replay policy.
func revokeRefreshFamily(userID string) error {
	_, err := db.GetDB().Exec(`UPDATE tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, time.Now().UTC(), userID)
	return err
}
