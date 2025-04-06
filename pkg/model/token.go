package model

import "time"

// Token represents a token record in the database
type Token struct {
	ID                     string     `db:"id"`                         // Unique token ID
	UserID                 string     `db:"user_id"`                    // The user to whom the token belongs
	AccessToken            string     `db:"access_token"`               // The actual access token (JWT or opaque token)
	RefreshToken           string     `db:"refresh_token"`              // The refresh token used for refreshing access tokens
	AccessTokenType        string     `db:"access_token_type"`          // Type of access token (e.g., 'Bearer', 'JWT')
	RefreshTokenExpiresAt  time.Time  `db:"refresh_token_expires_at"`   // Expiration time for the refresh token (if applicable)
	RefreshTokenLastUsedAt *time.Time `db:"refresh_token_last_used_at"` // Tracks when the refresh token was last used
	AccessTokenExpiresAt   time.Time  `db:"access_token_expires_at"`    // Expiration time for the access token
	IssuedAt               time.Time  `db:"issued_at"`                  // When the token was issued
	Scope                  string     `db:"scope"`                      // The scopes granted for this token (nullable)
	GrantType              string     `db:"grant_type"`                 // The OAuth2 grant type (e.g., 'authorization_code', 'client_credentials')
	RevokedAt              *time.Time `db:"revoked_at"`                 // Timestamp for when the token was revoked (nullable)
}
