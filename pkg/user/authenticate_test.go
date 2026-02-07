package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticateUser(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	user, err := AuthenticateUser("testuser", "password123")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticateUser_WrongPassword(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	_, err = AuthenticateUser("testuser", "wrongpassword")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid username or password")
}

func TestAuthenticateUser_NonExistentUser(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := AuthenticateUser("nonexistent", "password123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid username or password")
}
