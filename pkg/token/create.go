package token

import (
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"

	"github.com/rs/xid"
)

func CreateToken(token Token) error {
	query := `
		INSERT INTO tokens (
			id, user_id, access_token_hash, refresh_token_hash,
			access_token_type, refresh_token_expires_at,
			refresh_token_last_used_at, access_token_expires_at,
			issued_at, scope, grant_type, revoked_at, client_id, acr
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err := db.GetDB().Exec(query,
		xid.New().String(),
		token.UserID,
		utils.HashToken(token.AccessToken),
		utils.HashToken(token.RefreshToken),
		token.AccessTokenType,
		token.RefreshTokenExpiresAt,
		token.RefreshTokenLastUsedAt,
		token.AccessTokenExpiresAt,
		token.IssuedAt,
		token.Scope,
		token.GrantType,
		token.RevokedAt,
		token.ClientID,
		token.ACR,
	)

	return err
}
