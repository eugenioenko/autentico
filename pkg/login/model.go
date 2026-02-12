package login

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/config"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	State    string `json:"state"`
	Redirect string `json:"redirect"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	Nonce    string `json:"nonce"`
}

func ValidateLoginRequest(input LoginRequest) error {
	err := validation.Validate(
		input.Username,
		validation.Required,
		validation.Length(
			config.Get().ValidationMinUsernameLength,
			config.Get().ValidationMaxUsernameLength,
		),
	)
	if err != nil {
		return fmt.Errorf("username is invalid: %w", err)
	}

	err = validation.Validate(
		input.Password,
		validation.Required,
		validation.Length(
			config.Get().ValidationMinPasswordLength,
			config.Get().ValidationMaxPasswordLength,
		),
	)

	if err != nil {
		return fmt.Errorf("password is invalid: %w", err)
	}

	err = validation.Validate(
		input.Redirect,
		validation.Required,
		is.URL,
	)
	if err != nil {
		return fmt.Errorf("redirect URI is invalid: %w", err)
	}

	err = validation.Validate(
		input.State,
		validation.Required,
	)
	if err != nil {
		return fmt.Errorf("state is invalid: %w", err)
	}

	return nil
}
