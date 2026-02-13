package user

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
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
