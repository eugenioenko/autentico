package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestCreateUser(t *testing.T) {
	testutils.WithTestDB(t)

	u, err := CreateUser("testuser", "password123", "test@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, u)
	assert.Equal(t, "testuser", u.Username)
	assert.Equal(t, "test@example.com", u.Email)

	// Test duplicate username
	_, err = CreateUser("testuser", "password456", "other@example.com")
	assert.Error(t, err)
}

func TestCreatePasskeyUser(t *testing.T) {
	testutils.WithTestDB(t)

	ur, err := CreatePasskeyUser("passkeyuser", "pk@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, ur)
	assert.Equal(t, "passkeyuser", ur.Username)
	
	u, _ := UserByID(ur.ID)
	assert.Empty(t, u.Password)
}
