package model

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
		config.Values.ValidationEmailRequired = false
		config.Values.ValidationUsernameIsEmail = false
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "password123",
	})
	assert.NoError(t, err)
}

func TestValidateUserCreateRequest_InvalidUsername(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ValidationUsernameIsEmail = false
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "ab",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is invalid")
}

func TestValidateUserCreateRequest_InvalidPassword(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ValidationUsernameIsEmail = false
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "abc",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is invalid")
}

func TestValidateUserCreateRequest_UsernameIsEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ValidationUsernameIsEmail = true
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "not-email",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is invalid")
}

func TestValidateUserCreateRequest_EmailRequired(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ValidationEmailRequired = true
		config.Values.ValidationUsernameIsEmail = false
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "password123",
		Email:    "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is invalid")
}

func TestValidateUserCreateRequest_InvalidEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ValidationEmailRequired = false
		config.Values.ValidationUsernameIsEmail = false
	})

	err := ValidateUserCreateRequest(UserCreateRequest{
		Username: "testuser",
		Password: "password123",
		Email:    "not-an-email",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is invalid")
}
