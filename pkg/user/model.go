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
	ID                  string
	Username            string
	Password            string
	Email               string
	CreatedAt           time.Time
	Role                string
	FailedLoginAttempts int
	LockedUntil         *time.Time
	TotpSecret          string
	TotpVerified        bool
	IsEmailVerified     bool
	DeactivatedAt       *time.Time
	RegisteredAt        *time.Time
	UpdatedAt time.Time
	// OIDC standard profile claims
	GivenName         string
	FamilyName        string
	MiddleName        string
	Nickname          string
	Website           string
	Gender            string
	Birthdate         string
	ProfileURL          string
	PhoneNumber         string
	PhoneNumberVerified bool
	Picture             string
	Locale            string
	Zoneinfo          string
	AddressStreet     string
	AddressLocality   string
	AddressRegion     string
	AddressPostalCode string
	AddressCountry    string
}

type UserResponse struct {
	ID                  string     `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	CreatedAt           time.Time  `json:"created_at"`
	Role                string     `json:"role"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"locked_until,omitempty"`
	IsEmailVerified     bool       `json:"is_email_verified"`
	TotpVerified        bool       `json:"totp_verified"`
	Groups              []string   `json:"groups,omitempty"`
	// OIDC standard profile claims
	GivenName           string `json:"given_name,omitempty"`
	FamilyName          string `json:"family_name,omitempty"`
	MiddleName          string `json:"middle_name,omitempty"`
	Nickname            string `json:"nickname,omitempty"`
	Website             string `json:"website,omitempty"`
	Gender              string `json:"gender,omitempty"`
	Birthdate           string `json:"birthdate,omitempty"`
	ProfileURL          string `json:"profile,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
	Picture             string `json:"picture,omitempty"`
	Locale            string `json:"locale,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	AddressStreet     string `json:"address_street,omitempty"`
	AddressLocality   string `json:"address_locality,omitempty"`
	AddressRegion     string `json:"address_region,omitempty"`
	AddressPostalCode string `json:"address_postal_code,omitempty"`
	AddressCountry    string `json:"address_country,omitempty"`
}

// GetID satisfies the audit.Actor interface.
func (u *User) GetID() string { return u.ID }

// GetUsername satisfies the audit.Actor interface.
func (u *User) GetUsername() string { return u.Username }

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:                  u.ID,
		Username:            u.Username,
		Email:               u.Email,
		CreatedAt:           u.CreatedAt,
		Role:                u.Role,
		FailedLoginAttempts: u.FailedLoginAttempts,
		LockedUntil:         u.LockedUntil,
		IsEmailVerified:     u.IsEmailVerified,
		TotpVerified:        u.TotpVerified,
		GivenName:           u.GivenName,
		FamilyName:          u.FamilyName,
		MiddleName:          u.MiddleName,
		Nickname:            u.Nickname,
		Website:             u.Website,
		Gender:              u.Gender,
		Birthdate:           u.Birthdate,
		ProfileURL:          u.ProfileURL,
		PhoneNumber:         u.PhoneNumber,
		PhoneNumberVerified: u.PhoneNumberVerified,
		Picture:             u.Picture,
		Locale:              u.Locale,
		Zoneinfo:            u.Zoneinfo,
		AddressStreet:       u.AddressStreet,
		AddressLocality:     u.AddressLocality,
		AddressRegion:       u.AddressRegion,
		AddressPostalCode:   u.AddressPostalCode,
		AddressCountry:      u.AddressCountry,
	}
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
	Role     string `json:"role,omitempty"` // optional role assignment
}

type PasskeyUserCreateRequest struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
}

func ValidatePasskeyUserCreateRequest(input PasskeyUserCreateRequest) error {
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

	if config.Get().ProfileFieldEmail == "is_username" {
		if err = validation.Validate(input.Username, is.Email); err != nil {
			return fmt.Errorf("username is invalid: %w", err)
		}
	}

	if config.Get().ProfileFieldEmail == "required" || input.Email != "" {
		if err = validation.Validate(input.Email, validation.Required, is.Email); err != nil {
			return fmt.Errorf("email is invalid: %w", err)
		}
	}

	return nil
}

type UserUpdateRequest struct {
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	Email           string `json:"email,omitempty"`
	Role            string `json:"role,omitempty"`
	IsEmailVerified *bool  `json:"is_email_verified,omitempty"`
	TotpVerified    *bool  `json:"totp_verified,omitempty"`
	// OIDC standard profile claims
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	Website           string `json:"website,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	ProfileURL          string `json:"profile,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool  `json:"phone_number_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Locale            string `json:"locale,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	AddressStreet     string `json:"address_street,omitempty"`
	AddressLocality   string `json:"address_locality,omitempty"`
	AddressRegion     string `json:"address_region,omitempty"`
	AddressPostalCode string `json:"address_postal_code,omitempty"`
	AddressCountry    string `json:"address_country,omitempty"`
}

func ValidateUserUpdateRequest(input UserUpdateRequest) error {
	if input.Username != "" {
		if err := validation.Validate(input.Username, validation.Length(config.Get().ValidationMinUsernameLength, config.Get().ValidationMaxUsernameLength)); err != nil {
			return fmt.Errorf("username is invalid: %w", err)
		}
	}
	if input.Password != "" {
		if err := validation.Validate(input.Password, validation.Length(config.Get().ValidationMinPasswordLength, config.Get().ValidationMaxPasswordLength)); err != nil {
			return fmt.Errorf("password is invalid: %w", err)
		}
	}
	if input.Email != "" {
		if err := validation.Validate(input.Email, is.Email); err != nil {
			return fmt.Errorf("email is invalid: %w", err)
		}
	}
	if input.Role != "" {
		if err := validation.Validate(input.Role, validation.In("user", "admin")); err != nil {
			return fmt.Errorf("role is invalid: %w", err)
		}
	}
	return nil
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

	if config.Get().ProfileFieldEmail == "is_username" {
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

	if config.Get().ProfileFieldEmail == "required" || input.Email != "" {
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
