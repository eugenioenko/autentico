package introspect

import (
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// IntrospectToken looks up a token by access_token or refresh_token value and
// performs the checks required by RFC 7662 §4 (Security Considerations):
// - If the token can expire, determine whether it has expired.
// - If the token can be revoked, determine whether revocation has occurred.
// Returns nil with an error for any inactive state; the caller MUST return
// 200 {"active":false} per RFC 7662 §2.2.
func IntrospectToken(tokenID string) (*token.Token, error) {
	if tokenID == "" {
		return nil, errors.New("empty token")
	}
	hash := utils.HashToken(tokenID)
	query := `
		SELECT id, user_id, access_token_hash, refresh_token_hash,
			access_token_type, refresh_token_expires_at,
			refresh_token_last_used_at, access_token_expires_at,
			issued_at, scope, grant_type, revoked_at, client_id, acr
		FROM tokens WHERE access_token_hash = ? OR refresh_token_hash = ?;
	`
	var t token.Token
	row := db.GetDB().QueryRow(query, hash, hash)
	err := row.Scan(
		&t.ID, &t.UserID, &t.AccessTokenHash, &t.RefreshTokenHash,
		&t.AccessTokenType, &t.RefreshTokenExpiresAt, &t.RefreshTokenLastUsedAt,
		&t.AccessTokenExpiresAt, &t.IssuedAt, &t.Scope, &t.GrantType, &t.RevokedAt,
		&t.ClientID, &t.ACR,
	)

	if err != nil {
		return nil, err
	}

	// RFC 7662 §4: if the token can be revoked, the server MUST check revocation
	if t.RevokedAt != nil {
		return nil, errors.New("token has been revoked")
	}

	// RFC 7662 §4 / §2.2: check this credential at the same whole-second
	// precision as its signed JWT exp and the introspection response.
	if tokenExpired(&t, hash, time.Now()) {
		return nil, errors.New("token has expired")
	}

	return &t, nil
}

// tokenExpiration selects the lifetime of the presented credential after its
// hash has matched the stored token pair (RFC 7662 §2.2 and §4).
func tokenExpiration(t *token.Token, presentedHash string) time.Time {
	if presentedHash == t.AccessTokenHash {
		return t.AccessTokenExpiresAt
	}
	return t.RefreshTokenExpiresAt
}

// tokenExpired uses JWT exp precision and accepts now explicitly so both sides
// of the expiration-second boundary can be tested without a wall-clock race.
func tokenExpired(t *token.Token, presentedHash string, now time.Time) bool {
	return now.Unix() >= tokenExpiration(t, presentedHash).Unix()
}
