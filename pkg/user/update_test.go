package user

import (
	testutils "autentico/tests/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateUser(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user
	user, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Update the user's email
	err = UpdateUser(user.ID, "newemail@example.com")
	assert.NoError(t, err)

	// Verify the email was updated
	updatedUser, err := UserByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "newemail@example.com", updatedUser.Email)
}
