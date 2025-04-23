package token

import (
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
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

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}
