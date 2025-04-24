package token

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

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

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
}

func ValidateTokenRequest(input TokenRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.GrantType, validation.Required, validation.In("authorization_code", "refresh_token", "password")),
	)
}

func ValidateTokenRequestAuthorizationCode(input TokenRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.GrantType, validation.Required, validation.In("authorization_code")),
		validation.Field(&input.Code, validation.Required),
		validation.Field(&input.RedirectURI, validation.Required, is.URL),
		//validation.Field(&input.ClientID, validation.Required),
	)
}

func ValidateTokenRequestPassword(input TokenRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.GrantType, validation.Required, validation.In("password")),
		validation.Field(&input.Username, validation.Required),
		validation.Field(&input.Password, validation.Required),
	)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

type AuthToken struct {
	UserID           string
	AccessToken      string
	RefreshToken     string
	SessionID        string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}
