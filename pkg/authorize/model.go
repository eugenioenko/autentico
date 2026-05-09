package authorize

import (
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/authzsig"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
}

func ValidateAuthorizeRequest(input AuthorizeRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.ResponseType, validation.Required),
		validation.Field(&input.RedirectURI, validation.Required, is.URL),
		// RFC 6749 §3.3: validate scope token syntax
		validation.Field(&input.Scope, validation.By(validateScopeSyntax)),
	)
}

// validateScopeSyntax validates that the scope string conforms to RFC 6749 §3.3.
// Each scope token must consist of printable ASCII characters excluding
// double-quote, backslash, and space (which is the delimiter).
// NQCHAR = %x21 / %x23-5B / %x5D-7E
// An empty scope is allowed — the server may assign a default scope.
func validateScopeSyntax(value interface{}) error {
	scope, ok := value.(string)
	if !ok {
		return fmt.Errorf("scope must be a string")
	}
	if scope == "" {
		// RFC 6749 §3.3: if the client omits the scope parameter, the server
		// SHOULD either process the request using a pre-defined default or fail.
		// We allow empty and let the handler decide.
		return nil
	}
	for _, token := range strings.Fields(scope) {
		if err := validateScopeToken(token); err != nil {
			return err
		}
	}
	return nil
}

// validateScopeToken checks that a single scope token consists only of valid
// NQCHAR characters per RFC 6749 §3.3 (printable ASCII: 0x21, 0x23-0x5B, 0x5D-0x7E).
func validateScopeToken(token string) error {
	for _, ch := range token {
		if ch < 0x21 || ch > 0x7E || ch == 0x22 || ch == 0x5C {
			return fmt.Errorf("scope token %q contains invalid character", token)
		}
	}
	return nil
}

// AuthorizeSignature computes the HMAC signature for the authorize request parameters.
func AuthorizeSignature(request AuthorizeRequest) string {
	return authzsig.Sign(authzsig.AuthorizeParams{
		ClientID:            request.ClientID,
		RedirectURI:         request.RedirectURI,
		Scope:               request.Scope,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		State:               request.State,
	})
}

type AuthorizeErrorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
