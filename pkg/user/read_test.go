package user

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestListUsers(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = CreateUser("u1", "p1", "e1@test.com")
	_, _ = CreateUser("u2", "p2", "e2@test.com")

	users, err := ListUsers()
	assert.NoError(t, err)
	assert.Len(t, users, 2)
}

func TestUserByUsername(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = CreateUser("findme", "pass", "find@me.com")

	u, err := UserByUsername("findme")
	assert.NoError(t, err)
	assert.Equal(t, "findme", u.Username)

	_, err = UserByUsername("nonexistent")
	assert.Error(t, err)
}

func TestUserByID(t *testing.T) {
	testutils.WithTestDB(t)

	u1, _ := CreateUser("findbyid", "pass", "id@me.com")

	u, err := UserByID(u1.ID)
	assert.NoError(t, err)
	assert.Equal(t, u1.ID, u.ID)

	_, err = UserByID("invalid-id")
	assert.Error(t, err)
}

func TestUserByEmail(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("findbyemail", "pass", "email@test.com")
	// Verify email manually
	_, _ = db.GetDB().Exec("UPDATE users SET is_email_verified = TRUE WHERE id = ?", u.ID)

	uFound, err := UserByEmail("email@test.com")
	assert.NoError(t, err)
	assert.Equal(t, "findbyemail", uFound.Username)

	_, err = UserByEmail("none@test.com")
	assert.Error(t, err)
}

func TestUserExistsByEmail(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("existuser", "pass", "exists@test.com")
	// Verify email manually
	_, _ = db.GetDB().Exec("UPDATE users SET is_email_verified = TRUE WHERE id = ?", u.ID)

	assert.True(t, UserExistsByEmail("exists@test.com"))
	assert.False(t, UserExistsByEmail("notexists@test.com"))
}

func TestCountUsers(t *testing.T) {
	testutils.WithTestDB(t)

	count, _ := CountUsers()
	assert.Equal(t, 0, count)

	_, _ = CreateUser("u1", "p1", "e1@test.com")
	_, _ = CreateUser("u2", "p2", "e2@test.com")

	count, _ = CountUsers()
	assert.Equal(t, 2, count)
}
