package authorize

import (
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
		// TODO: set proper scope validation
		//validation.Field(&input.Scope, validation.Required, validation.In("read", "write")),
	)
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
