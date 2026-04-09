package user

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeactivateUser(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("deluser", "pass", "del@example.com")
	err := DeactivateUser(u.ID)
	assert.NoError(t, err)

	// Verify deactivated using raw SQL because UserByID filters them out
	var deactivatedAt *string
	err = db.GetDB().QueryRow("SELECT deactivated_at FROM users WHERE id = ?", u.ID).Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.NotNil(t, deactivatedAt)
}

func TestDeactivateUser_AlreadyDeactivated(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("deluser2", "pass", "del2@example.com")
	err := DeactivateUser(u.ID)
	require.NoError(t, err)

	// Deactivating again should fail
	err = DeactivateUser(u.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found or already deactivated")
}

func TestReactivateUser(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("reactuser", "pass", "react@example.com")
	err := DeactivateUser(u.ID)
	require.NoError(t, err)

	// Verify deactivated
	_, err = UserByID(u.ID)
	assert.Error(t, err)

	// Reactivate
	err = ReactivateUser(u.ID)
	assert.NoError(t, err)

	// Verify active again
	found, err := UserByID(u.ID)
	assert.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
}

func TestReactivateUser_NotDeactivated(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("reactuser2", "pass", "react2@example.com")
	err := ReactivateUser(u.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found or not deactivated")
}

func TestHardDeleteUser(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("harddeluser", "pass", "harddel@example.com")
	err := HardDeleteUser(u.ID)
	assert.NoError(t, err)

	// Verify gone from DB
	var count int
	_ = db.GetDB().QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", u.ID).Scan(&count)
	assert.Equal(t, 0, count)
}
