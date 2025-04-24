package login

import (
	"autentico/pkg/config"
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	State    string `json:"state"`
	Redirect string `json:"redirect"`
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

	return nil
}
