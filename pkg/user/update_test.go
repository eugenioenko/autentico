package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestUpdateUser(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user
	user, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Update the user's email and role
	err = UpdateUser(user.ID, "newemail@example.com", user.Role)
	assert.NoError(t, err)

	// Verify the email was updated
	updatedUser, err := UserByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "newemail@example.com", updatedUser.Email)
}

func TestSaveTotpSecret(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("u1", "p", "e1")

	err := SaveTotpSecret(u.ID, "SECRET123")
	assert.NoError(t, err)

	updated, _ := UserByID(u.ID)
	assert.Equal(t, "SECRET123", updated.TotpSecret)
	assert.True(t, updated.TotpVerified)
}

