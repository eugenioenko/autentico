package model

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
		return fmt.Errorf("Token is required: %w", err)
	}

	return nil
}
