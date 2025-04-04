package tokens

import (
	"autentico/pkg/db"
	. "autentico/pkg/models"

	"github.com/rs/xid"
)

func CreateToken(token Token) error {
	query := `
		INSERT INTO tokens (
			id, user_id, access_token, refresh_token,
			access_token_type, refresh_token_expires_at,
			refresh_token_last_used_at, access_token_expires_at,
			issued_at, scope, grant_type, revoked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err := db.GetDB().Exec(query,
		xid.New().String(),
		token.UserID,
		token.AccessToken,
		token.RefreshToken,
		token.AccessTokenType,
		token.RefreshTokenExpiresAt,
		token.RefreshTokenLastUsedAt,
		token.AccessTokenExpiresAt,
		token.IssuedAt,
		token.Scope,
		token.GrantType,
		token.RevokedAt,
	)

	return err
}
