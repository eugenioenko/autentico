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

// IntrospectResponse represents the RFC 7662 §2.2 introspection response.
// "active" is REQUIRED; all other fields are OPTIONAL per the spec.
type IntrospectResponse struct {
	Active           bool   `json:"active"`               // RFC 7662 §2.2: REQUIRED. Whether the token is currently active.
	Scope            string `json:"scope,omitempty"`      // RFC 7662 §2.2: OPTIONAL. Space-delimited list of scopes.
	ClientID         string `json:"client_id,omitempty"`  // RFC 7662 §2.2: OPTIONAL. Client that requested this token.
	Username         string `json:"username,omitempty"`   // RFC 7662 §2.2: OPTIONAL. Human-readable resource owner identifier.
	TokenType        string `json:"token_type,omitempty"` // RFC 7662 §2.2: OPTIONAL. Type of the token (e.g., "bearer").
	Exp              int64  `json:"exp,omitempty"`        // RFC 7662 §2.2: OPTIONAL. Expiration time (Unix timestamp).
	Iat              int64  `json:"iat,omitempty"`        // RFC 7662 §2.2: OPTIONAL. Issued-at time (Unix timestamp).
	Sub              string `json:"sub,omitempty"`        // RFC 7662 §2.2: OPTIONAL. Subject of the token.
	Aud              string `json:"aud,omitempty"`        // RFC 7662 §2.2: OPTIONAL. Intended audience.
	Iss              string `json:"iss,omitempty"`        // RFC 7662 §2.2: OPTIONAL. Issuer of this token.
	Nbf              int64  `json:"nbf,omitempty"`        // RFC 7662 §2.2: OPTIONAL. Not-before time (Unix timestamp).
	Jti              string `json:"jti,omitempty"`        // RFC 7662 §2.2: OPTIONAL. Unique identifier for the token.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
