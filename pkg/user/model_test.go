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

func TestValidateURLScheme(t *testing.T) {
	// Valid http URL
	err := validateURLScheme("http://example.com/photo.jpg")
	assert.NoError(t, err)

	// Valid https URL
	err = validateURLScheme("https://example.com/photo.jpg")
	assert.NoError(t, err)

	// javascript: scheme rejected
	err = validateURLScheme("javascript:alert(1)")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http or https")

	// file: scheme rejected
	err = validateURLScheme("file:///etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http or https")

	// data: scheme rejected
	err = validateURLScheme("data:text/html,<script>alert(1)</script>")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http or https")

	// Relative URL without scheme rejected
	err = validateURLScheme("example.com/photo.jpg")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http or https")
}

func TestValidateUserUpdateRequest_URLFields(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
	})

	// Empty URL fields are allowed (optional)
	err := ValidateUserUpdateRequest(UserUpdateRequest{
		Picture:    "",
		Website:    "",
		ProfileURL: "",
	})
	assert.NoError(t, err)

	// Valid https URLs pass
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Picture:    "https://example.com/photo.jpg",
		Website:    "https://example.com",
		ProfileURL: "https://example.com/profile",
	})
	assert.NoError(t, err)

	// Valid http URLs pass
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Picture:    "http://example.com/photo.jpg",
		Website:    "http://example.com",
		ProfileURL: "http://example.com/profile",
	})
	assert.NoError(t, err)

	// javascript: in Picture rejected
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Picture: "javascript:alert(1)",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "picture is invalid")

	// javascript: in Website rejected
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Website: "javascript:alert(1)",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "website is invalid")

	// javascript: in ProfileURL rejected
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		ProfileURL: "javascript:alert(1)",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "profile URL is invalid")

	// file: scheme rejected
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Picture: "file:///etc/passwd",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "picture is invalid")

	// Relative URL without scheme rejected
	err = ValidateUserUpdateRequest(UserUpdateRequest{
		Website: "example.com/page",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "website is invalid")
}
