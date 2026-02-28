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

func TestUserByID_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := UserByID("nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestCountUsers(t *testing.T) {
	testutils.WithTestDB(t)
	count, err := CountUsers()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	_, _ = CreateUser("u1", "p", "e1")
	_, _ = CreateUser("u2", "p", "e2")

	count, err = CountUsers()
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestUserByUsername(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = CreateUser("user1", "p", "e1")

	u, err := UserByUsername("user1")
	assert.NoError(t, err)
	assert.Equal(t, "user1", u.Username)

	_, err = UserByUsername("nonexistent")
	assert.Error(t, err)
}

