package introspect

import (
	"autentico/pkg/db"
	"autentico/pkg/token"
	"errors"
	"time"
)

func IntrospectToken(tokenId string) (*token.Token, error) {
	query := `
		SELECT id, user_id, access_token, refresh_token,
			access_token_type, refresh_token_expires_at,
			refresh_token_last_used_at, access_token_expires_at,
			issued_at, scope, grant_type, revoked_at
		FROM tokens WHERE access_token = ? OR refresh_token = ?;
	`
	var t token.Token
	row := db.GetDB().QueryRow(query, tokenId)
	err := row.Scan(
		&t.ID, &t.UserID, &t.AccessToken, &t.RefreshToken,
		&t.AccessTokenType, &t.RefreshTokenExpiresAt, &t.RefreshTokenLastUsedAt,
		&t.AccessTokenExpiresAt, &t.IssuedAt, &t.Scope, &t.GrantType, &t.RevokedAt,
	)

	if err != nil {
		return nil, err
	}

	if t.RevokedAt != nil {
		return nil, errors.New("token has been revoked")
	}

	if time.Now().After(t.AccessTokenExpiresAt) {
		return nil, errors.New("token has expired")
	}

	return &t, nil
}
