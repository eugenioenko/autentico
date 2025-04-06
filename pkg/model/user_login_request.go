package model

import (
	"autentico/pkg/config"
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation"
)

type UserLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func ValidateUserLoginRequest(input UserLoginRequest) error {
	err := validation.Validate(
		input.Username,
		validation.Required,
		validation.Length(
			config.Get().ValidationMinUsernameLength,
			config.Get().ValidationMaxUsernameLength,
		),
	)
	if err != nil {
		return fmt.Errorf("Username is invalid: %w", err)
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
		return fmt.Errorf("Password is invalid: %w", err)
	}

	return nil
}
