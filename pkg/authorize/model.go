package authorize

import (
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
}

func ValidateAuthorizeRequest(input AuthorizeRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.ResponseType, validation.Required, validation.In("code")),
		validation.Field(&input.RedirectURI, validation.Required, is.URL),
		// TODO: set proper scope validation
		//validation.Field(&input.Scope, validation.Required, validation.In("read", "write")),
	)
}

type AuthorizeErrorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
