package token

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// TokenByAccessToken returns the active token row matching the access token.
// Revoked tokens are filtered at the read layer so callers can't accidentally
// honor a revoked token.
//
// Returns sql.ErrNoRows when no active row exists. A JWT that validated
// cryptographically but has no matching active row means either (a) the
// token was revoked via /oauth2/revoke, (b) its tokens row was cleaned up
// because the refresh token expired (only possible if refresh_token_expiration
// is misconfigured shorter than access_token_expiration), or (c) the JWT was
// forged (impossible with an uncompromised signing key). Callers should
// treat this as a rejection, not a pass.
func TokenByAccessToken(accessToken string) (*Token, error) {
	var t Token
	err := db.GetDB().QueryRow(`
		SELECT id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, refresh_token_last_used_at,
			access_token_expires_at, issued_at, scope, grant_type, revoked_at
		FROM tokens WHERE access_token = ? AND revoked_at IS NULL
	`, accessToken).Scan(
		&t.ID, &t.UserID, &t.AccessToken, &t.RefreshToken, &t.AccessTokenType,
		&t.RefreshTokenExpiresAt, &t.RefreshTokenLastUsedAt,
		&t.AccessTokenExpiresAt, &t.IssuedAt, &t.Scope, &t.GrantType, &t.RevokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	return &t, nil
}
