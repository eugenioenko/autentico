package introspect

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation"
)

type IntrospectRequest struct {
	Token string `json:"token"`
}

func ValidateTokenIntrospectRequest(input IntrospectRequest) error {
	err := validation.Validate(
		input.Token,
		validation.Required,
	)
	if err != nil {
		return fmt.Errorf("token is required: %w", err)
	}

	return nil
}

type IntrospectResponse struct {
	Active           bool   `json:"active"`               // Whether the token is valid (true or false).
	Scope            string `json:"scope,omitempty"`      // Space-delimited list of scopes associated with the token.
	ClientID         string `json:"client_id,omitempty"`  // Client ID for which the token was issued.
	Username         string `json:"username,omitempty"`   // The username of the authenticated user.
	TokenType        string `json:"token_type,omitempty"` // The type of the token (usually "bearer").
	Exp              int64  `json:"exp,omitempty"`        // Expiration time (Unix timestamp).
	Iat              int64  `json:"iat,omitempty"`        // Issued-at time (Unix timestamp).
	Sub              string `json:"sub,omitempty"`        // The subject of the token (typically the user ID).
	Aud              string `json:"aud,omitempty"`        // Intended audience for the token (e.g., the API).
	Nbf              int64  `json:"nbf,omitempty"`        // Not-before time (Unix timestamp).
	Jti              string `json:"jti,omitempty"`        // Unique identifier for the token.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
