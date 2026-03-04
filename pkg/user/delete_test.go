package user

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestDeleteUser(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("deluser", "pass", "del@example.com")
	err := DeleteUser(u.ID)
	assert.NoError(t, err)

	// Verify deactivated using raw SQL because UserByID filters them out
	var deactivatedAt *string
	err = db.GetDB().QueryRow("SELECT deactivated_at FROM users WHERE id = ?", u.ID).Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.NotNil(t, deactivatedAt)
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
