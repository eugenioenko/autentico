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
