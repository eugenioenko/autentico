package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestCreateUser(t *testing.T) {
	testutils.WithTestDB(t)

	user, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "testuser@example.com", user.Email)
	assert.NotEmpty(t, user.ID)
	assert.False(t, user.CreatedAt.IsZero())
}

func TestCreateUser_DuplicateUsername(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := CreateUser("testuser", "password123", "test1@example.com")
	assert.NoError(t, err)

	_, err = CreateUser("testuser", "password456", "test2@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create user")
}
