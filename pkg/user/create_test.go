package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCreateUser_SetsRegisteredAt(t *testing.T) {
	testutils.WithTestDB(t)

	u, err := CreateUser("reguser", "password123", "reg@example.com")
	require.NoError(t, err)

	fetched, err := UserByID(u.ID)
	require.NoError(t, err)
	assert.NotNil(t, fetched.RegisteredAt, "password users must have registered_at set at creation")
}

func TestCreatePasskeyUser_RegisteredAtIsNil(t *testing.T) {
	testutils.WithTestDB(t)

	ur, err := CreatePasskeyUser("pendingpkuser", "pending@example.com")
	require.NoError(t, err)

	u, err := UserByID(ur.ID)
	require.NoError(t, err)
	assert.Nil(t, u.RegisteredAt, "passkey users must have registered_at = NULL until ceremony completes")
}
