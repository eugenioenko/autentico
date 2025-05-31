package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestDeleteUser(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user
	user, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Delete the user
	err = DeleteUser(user.ID)
	assert.NoError(t, err)

	// Verify the user no longer exists
	_, err = UserByID(user.ID)
	assert.Error(t, err)
}
