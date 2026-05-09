package user

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticateUser(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	user, err := AuthenticateUser("testuser", "password123")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticateUser_WrongPassword(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	_, err = AuthenticateUser("testuser", "wrongpassword")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid username or password")
}

func TestAuthenticateUser_NonExistentUser(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := AuthenticateUser("nonexistent", "password123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid username or password")
}

func TestAuthenticateUser_LockoutAfterMaxAttempts(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 3
		config.Values.AuthAccountLockoutDuration = 15 * time.Minute
	})

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Fail 3 times
	for i := 0; i < 3; i++ {
		_, err = AuthenticateUser("testuser", "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid username or password")
	}

	// 4th attempt should be locked, even with correct password
	_, err = AuthenticateUser("testuser", "password123")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountLocked)
}

func TestAuthenticateUser_LockoutExpires(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 3
		config.Values.AuthAccountLockoutDuration = 15 * time.Minute
	})

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Fail 3 times to trigger lockout
	for i := 0; i < 3; i++ {
		_, err = AuthenticateUser("testuser", "wrongpassword")
		assert.Error(t, err)
	}

	// Set locked_until to the past to simulate expiry
	pastTime := time.Now().Add(-1 * time.Minute)
	_, err = db.GetDB().Exec(`UPDATE users SET locked_until = ? WHERE username = ?`, pastTime, "testuser")
	assert.NoError(t, err)

	// Should succeed now
	user, err := AuthenticateUser("testuser", "password123")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticateUser_ResetOnSuccess(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 5
		config.Values.AuthAccountLockoutDuration = 15 * time.Minute
	})

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Fail 3 times (below threshold of 5)
	for i := 0; i < 3; i++ {
		_, err = AuthenticateUser("testuser", "wrongpassword")
		assert.Error(t, err)
	}

	// Succeed — should reset counter
	user, err := AuthenticateUser("testuser", "password123")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	// Fail 4 more times — should NOT lock because counter was reset
	for i := 0; i < 4; i++ {
		_, err = AuthenticateUser("testuser", "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid username or password")
	}

	// 5th failure should lock
	_, err = AuthenticateUser("testuser", "wrongpassword")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid username or password")

	// Now locked
	_, err = AuthenticateUser("testuser", "password123")
	assert.ErrorIs(t, err, ErrAccountLocked)
}

func TestAuthenticateUser_LockoutDisabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 0
	})

	_, err := CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Fail many times — should never lock
	for i := 0; i < 20; i++ {
		_, err = AuthenticateUser("testuser", "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid username or password")
	}

	// Should still succeed
	user, err := AuthenticateUser("testuser", "password123")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticateUser_LockoutDirect(t *testing.T) {
	testutils.WithTestDB(t)
	
	userID := "u1"
	username := "lockeduser"
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, locked_until) 
		VALUES (?, ?, 'l@test.com', 'pass', datetime('now', '+1 hour'))
	`, userID, username)

	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 5

		_, err := AuthenticateUser(username, "any")
		assert.Error(t, err)
		assert.Equal(t, ErrAccountLocked, err)
	})
}

func createTestUserWithPassword(t *testing.T, id, password string) *User {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		id, id, id+"@test.com", string(hashed),
	)
	require.NoError(t, err)
	usr, err := UserByID(id)
	require.NoError(t, err)
	return usr
}

func TestVerifyPasswordWithLockout_CorrectPassword(t *testing.T) {
	testutils.WithTestDB(t)
	usr := createTestUserWithPassword(t, "u1", "secret")

	err := verifyPasswordWithLockout(usr, "secret")
	assert.NoError(t, err)
}

func TestVerifyPasswordWithLockout_WrongPassword(t *testing.T) {
	testutils.WithTestDB(t)
	usr := createTestUserWithPassword(t, "u1", "secret")

	err := verifyPasswordWithLockout(usr, "wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")
}

func TestVerifyPasswordWithLockout_IncrementsFailedAttempts(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 5
		config.Values.AuthAccountLockoutDuration = 15 * time.Minute
	})
	usr := createTestUserWithPassword(t, "u1", "secret")

	_ = verifyPasswordWithLockout(usr, "wrong")

	updated, _ := UserByID("u1")
	assert.Equal(t, 1, updated.FailedLoginAttempts)
}

func TestVerifyPasswordWithLockout_LocksAfterMaxAttempts(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 3
		config.Values.AuthAccountLockoutDuration = 15 * time.Minute
	})
	createTestUserWithPassword(t, "u1", "secret")

	for i := 0; i < 3; i++ {
		usr, _ := UserByID("u1")
		_ = verifyPasswordWithLockout(usr, "wrong")
	}

	usr, _ := UserByID("u1")
	err := verifyPasswordWithLockout(usr, "secret")
	assert.ErrorIs(t, err, ErrAccountLocked)
}

func TestVerifyPasswordWithLockout_ResetsOnSuccess(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 5
		config.Values.AuthAccountLockoutDuration = 15 * time.Minute
	})
	createTestUserWithPassword(t, "u1", "secret")

	for i := 0; i < 3; i++ {
		usr, _ := UserByID("u1")
		_ = verifyPasswordWithLockout(usr, "wrong")
	}

	usr, _ := UserByID("u1")
	err := verifyPasswordWithLockout(usr, "secret")
	assert.NoError(t, err)

	updated, _ := UserByID("u1")
	assert.Equal(t, 0, updated.FailedLoginAttempts)
	assert.Nil(t, updated.LockedUntil)
}

func TestVerifyPasswordWithLockout_AlreadyLocked(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 5
	})
	usr := createTestUserWithPassword(t, "u1", "secret")

	lockUntil := time.Now().Add(1 * time.Hour)
	_, _ = db.GetDB().Exec(`UPDATE users SET locked_until = ? WHERE id = ?`, lockUntil, usr.ID)
	usr, _ = UserByID("u1")

	err := verifyPasswordWithLockout(usr, "secret")
	assert.ErrorIs(t, err, ErrAccountLocked)
}

func TestVerifyPasswordWithLockout_LockoutDisabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 0
	})
	createTestUserWithPassword(t, "u1", "secret")

	for i := 0; i < 20; i++ {
		usr, _ := UserByID("u1")
		_ = verifyPasswordWithLockout(usr, "wrong")
	}

	usr, _ := UserByID("u1")
	err := verifyPasswordWithLockout(usr, "secret")
	assert.NoError(t, err)
}
