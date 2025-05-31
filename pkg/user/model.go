package user

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/model"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

type User struct {
	ID        string
	Username  string
	Password  string
	Email     string
	CreatedAt time.Time
}

type UserResponse struct {
	ID        string
	Username  string
	Email     string
	CreatedAt time.Time
}

// ApiUserResponse is used for Swagger documentation
type ApiUserResponse struct {
	Data  *UserResponse   `json:"data,omitempty"`
	Error *model.ApiError `json:"error,omitempty"`
}

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
			config.Get().ValidationMinUsernameLength,
			config.Get().ValidationMaxUsernameLength,
		),
	)
	if err != nil {
		return fmt.Errorf("username is invalid: %w", err)
	}

	if config.Get().ValidationUsernameIsEmail {
		err = validation.Validate(
			input.Username,
			is.Email,
		)
		if err != nil {
			return fmt.Errorf("username is invalid: %w", err)
		}
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

	if config.Get().ValidationEmailRequired || input.Email != "" {
		err = validation.Validate(
			input.Email,
			validation.Required,
			is.Email,
		)
		if err != nil {
			return fmt.Errorf("email is invalid: %w", err)
		}
	}

	return nil
}
