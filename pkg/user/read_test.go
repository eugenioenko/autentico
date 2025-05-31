package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestUserByID(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a test user
	createdUser, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Fetch the user by ID
	readUser, err := UserByID(createdUser.ID)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", readUser.Username)
	assert.Equal(t, "testuser@example.com", readUser.Email)
}
