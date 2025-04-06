package model

import (
	"autentico/pkg/config"
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

type UserCreateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
}

func ValidateUserCreateRequest(input UserCreateRequest) error {
	err := validation.Validate(
		input.Username,
		validation.Required,
		validation.Length(
			config.ValidationMinUsernameLength,
			config.ValidationMaxUsernameLength,
		),
	)
	if err != nil {
		return fmt.Errorf("Username is invalid: %w", err)
	}

	if config.ValidationUsernameIsEmail {
		err = validation.Validate(
			input.Username,
			is.Email,
		)
		if err != nil {
			return fmt.Errorf("Username is invalid: %w", err)
		}
	}

	err = validation.Validate(
		input.Password,
		validation.Required,
		validation.Length(
			config.ValidationMinPasswordLength,
			config.ValidationMaxPasswordLength,
		),
	)
	if err != nil {
		return fmt.Errorf("Password is invalid: %w", err)
	}

	if config.ValidationEmailRequired || input.Email != "" {
		err = validation.Validate(
			input.Email,
			validation.Required,
			is.Email,
		)
		if err != nil {
			return fmt.Errorf("Email is invalid: %w", err)
		}
	}

	return nil
}
