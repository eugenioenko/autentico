package token

import (
	"fmt"
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
	GrantType    string `json:"grant_type"`              // The OAuth2 grant type (e.g., 'authorization_code', 'refresh_token', 'password')
	Code         string `json:"code"`                    // The authorization code received from the authorization server
	RedirectURI  string `json:"redirect_uri"`            // The redirect URI used in the authorization request
	ClientID     string `json:"client_id"`               // The client ID of the application making the request
	ClientSecret string `json:"client_secret,omitempty"` // The client secret (optional, depending on the grant type)
	CodeVerifier string `json:"code_verifier,omitempty"` // The code verifier for PKCE (optional, depending on the grant type)
	Username     string `json:"username,omitempty"`      // The username for the resource owner (used in password grant type)
	Password     string `json:"password,omitempty"`      // The password for the resource owner (used in password grant type)
	RefreshToken string `json:"refresh_token,omitempty"` // The refresh token (used in refresh token grant type)
}

type RefreshTokenClaims struct {
	UserID    string `json:"sub"` // The ID of the user associated with the refresh token
	SessionID string `json:"sid"` // The session ID for which the refresh token is issued
	IssuedAt  int64  `json:"iat"` // The timestamp when the refresh token was issued
	ExpiresAt int64  `json:"exp"` // The timestamp when the refresh token will expire
}

func (r *RefreshTokenClaims) Valid() error {
	if time.Unix(r.ExpiresAt, 0).Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}
	return nil
}

type AccessTokenClaims struct {
	UserID    string `json:"sub"`   // The ID of the user associated with the access token
	Email     string `json:"email"` // The email of the user associated with the access token
	SessionID string `json:"sid"`   // The session ID for which the access token is issued
	IssuedAt  int64  `json:"iat"`   // The timestamp when the access token was issued
	ExpiresAt int64  `json:"exp"`   // The timestamp when the access token will expire
	Audience  string `json:"aud"`   // The audience for which the access token is intended
	Issuer    string `json:"iss"`   // The issuer of the access token
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
		// validation.Field(&input.ClientID, validation.Required),
	)
}

func ValidateTokenRequestPassword(input TokenRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.GrantType, validation.Required, validation.In("password")),
		validation.Field(&input.Username, validation.Required),
		validation.Field(&input.Password, validation.Required),
	)
}

func ValidateTokenRequestRefresh(input TokenRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.GrantType, validation.Required, validation.In("refresh_token")),
		validation.Field(&input.RefreshToken, validation.Required),
		// validation.Field(&input.ClientID, validation.Required),
		// validation.Field(&input.CodeVerifier, validation.Required),
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
