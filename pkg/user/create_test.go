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
}
