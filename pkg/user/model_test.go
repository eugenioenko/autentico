package user

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestValidateUserCreateRequest_Valid(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "password123",
	})
	assert.NoError(t, err)
}

func TestValidateUserCreateRequest_ShortUsername(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "ab",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is invalid")
}

func TestValidateUserCreateRequest_EmptyUsername(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is invalid")
}

func TestValidateUserCreateRequest_ShortPassword(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "abc",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is invalid")
}

func TestValidateUserCreateRequest_EmptyPassword(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is invalid")
}

func TestValidateUserCreateRequest_InvalidEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "password123",
		Email:    "not-an-email",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is invalid")
}

func TestValidateUserCreateRequest_EmailRequired(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "required"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "password123",
		Email:    "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is invalid")
}

func TestValidateUserCreateRequest_UsernameIsEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "is_username"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "not-an-email",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is invalid")
}

func TestValidateUserCreateRequest_UsernameIsEmail_Valid(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "is_username"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "user@example.com",
		Password: "password123",
	})
	assert.NoError(t, err)
}

func TestValidateUserCreateRequest_ValidEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "required"
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "password123",
		Email:    "user@example.com",
	})
	assert.NoError(t, err)
}

func TestValidatePasskeyUserCreateRequest(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ProfileFieldEmail = "hidden"
	})

	// Valid
	err := ValidatePasskeyUserCreateRequest(PasskeyUserCreateRequest{
		Username: "testuser",
	})
	assert.NoError(t, err)

	// Invalid username
	err = ValidatePasskeyUserCreateRequest(PasskeyUserCreateRequest{
		Username: "a",
	})
	assert.Error(t, err)
}

func TestValidateUserUpdateRequest(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
	})

	// Valid
	err := ValidateUserUpdateRequest(UserUpdateRequest{
		Username: "newname",
		Email:    "new@email.com",
	})
	assert.NoError(t, err)

	// Invalid username
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Username: "a",
	})
	assert.Error(t, err)

	// Invalid email
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Email: "not-an-email",
	})
	assert.Error(t, err)
}
