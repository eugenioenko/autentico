package introspect

import (
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
)

// IntrospectToken looks up a token by access_token or refresh_token value and
// performs the checks required by RFC 7662 §4 (Security Considerations):
// - If the token can expire, determine whether it has expired.
// - If the token can be revoked, determine whether revocation has occurred.
// Returns nil with an error for any inactive state; the caller MUST return
// 200 {"active":false} per RFC 7662 §2.2.
func IntrospectToken(tokenID string) (*token.Token, error) {
	query := `
		SELECT id, user_id, access_token, refresh_token,
			access_token_type, refresh_token_expires_at,
			refresh_token_last_used_at, access_token_expires_at,
			issued_at, scope, grant_type, revoked_at
		FROM tokens WHERE access_token = ? OR refresh_token = ?;
	`
	var t token.Token
	row := db.GetReadDB().QueryRow(query, tokenID, tokenID)
	err := row.Scan(
		&t.ID, &t.UserID, &t.AccessToken, &t.RefreshToken,
		&t.AccessTokenType, &t.RefreshTokenExpiresAt, &t.RefreshTokenLastUsedAt,
		&t.AccessTokenExpiresAt, &t.IssuedAt, &t.Scope, &t.GrantType, &t.RevokedAt,
	)

	if err != nil {
		return nil, err
	}

	// RFC 7662 §4: if the token can be revoked, the server MUST check revocation
	if t.RevokedAt != nil {
		return nil, errors.New("token has been revoked")
	}

	// RFC 7662 §4: if the token can expire, the server MUST check expiry
	if time.Now().After(t.AccessTokenExpiresAt) {
		return nil, errors.New("token has expired")
	}

	return &t, nil
}
