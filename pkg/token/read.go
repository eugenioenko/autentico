package token

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// TokenByAccessToken returns the token row matching the given access token
// value. Returns sql.ErrNoRows when no row exists — not every flow persists
// a tokens row (e.g. some short-lived paths), so callers should treat
// "not found" as "nothing to check" rather than a rejection.
func TokenByAccessToken(accessToken string) (*Token, error) {
	var t Token
	err := db.GetDB().QueryRow(`
		SELECT id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, refresh_token_last_used_at,
			access_token_expires_at, issued_at, scope, grant_type, revoked_at
		FROM tokens WHERE access_token = ?
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
