package user

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestDeleteUser(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user
	user, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Soft delete the user
	err = DeleteUser(user.ID)
	assert.NoError(t, err)

	// User should still exist in DB (soft delete)
	_, err = UserByID(user.ID)
	assert.NoError(t, err)

	// But should have deactivated_at set
	var deactivatedAt *string
	row := db.GetDB().QueryRow(`SELECT deactivated_at FROM users WHERE id = ?`, user.ID)
	err = row.Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.NotNil(t, deactivatedAt)
}

func TestDeleteUser_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	err := DeleteUser("nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}
