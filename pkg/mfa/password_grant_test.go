package mfa

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passwordGrantTotpUser creates an enrolled account with a valid and an invalid numeric code.
func passwordGrantTotpUser(t *testing.T) (string, string, string) {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutDuration = 2 * time.Minute
	})
	usr, err := user.CreateUser("totp-budget", "password123", "totp-budget@example.com")
	require.NoError(t, err)
	const secret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))
	valid, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	for i := 0; i < 1000000; i++ {
		invalid := fmt.Sprintf("%06d", i)
		if !ValidateTotpCode(secret, invalid) {
			return usr.ID, valid, invalid
		}
	}
	t.Fatal("could not find an invalid TOTP")
	return "", "", ""
}

// TestPasswordGrantTotpLockout preserves failures across password checks and rejects valid codes during cooldown.
func TestPasswordGrantTotpLockout(t *testing.T) {
	userID, valid, invalid := passwordGrantTotpUser(t)
	for range maxTotpAttempts - 1 {
		require.ErrorIs(t, VerifyPasswordGrantTotp(userID, invalid), ErrInvalidTotp)
		_, err := user.AuthenticateUser("totp-budget", "password123")
		require.NoError(t, err)
	}
	require.ErrorIs(t, VerifyPasswordGrantTotp(userID, invalid), ErrTotpLocked)
	var attempts int
	var lockedUntil *time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_failed_attempts, totp_locked_until FROM users WHERE id = ?`, userID).Scan(&attempts, &lockedUntil))
	assert.Equal(t, maxTotpAttempts, attempts)
	require.NotNil(t, lockedUntil)
	assert.WithinDuration(t, time.Now().Add(2*time.Minute), *lockedUntil, time.Second)
	require.ErrorIs(t, VerifyPasswordGrantTotp(userID, valid), ErrTotpLocked)

	_, err := db.GetDB().Exec(`UPDATE users SET totp_locked_until = ? WHERE id = ?`, time.Now().Add(-time.Second), userID)
	require.NoError(t, err)
	require.NoError(t, VerifyPasswordGrantTotp(userID, valid))
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_failed_attempts, totp_locked_until FROM users WHERE id = ?`, userID).Scan(&attempts, &lockedUntil))
	assert.Zero(t, attempts)
	assert.Nil(t, lockedUntil)
}

// TestPasswordGrantTotpSuccessResetsFailures starts a new budget after successful MFA.
func TestPasswordGrantTotpSuccessResetsFailures(t *testing.T) {
	userID, valid, invalid := passwordGrantTotpUser(t)
	for range maxTotpAttempts - 1 {
		require.ErrorIs(t, VerifyPasswordGrantTotp(userID, invalid), ErrInvalidTotp)
	}
	require.NoError(t, VerifyPasswordGrantTotp(userID, valid))
	require.ErrorIs(t, VerifyPasswordGrantTotp(userID, invalid), ErrInvalidTotp)
	var attempts int
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_failed_attempts FROM users WHERE id = ?`, userID).Scan(&attempts))
	assert.Equal(t, 1, attempts)
}

// TestPasswordGrantTotpConcurrentFailures bounds guesses even when requests arrive together.
func TestPasswordGrantTotpConcurrentFailures(t *testing.T) {
	userID, _, invalid := passwordGrantTotpUser(t)
	results := make(chan error, 20)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range cap(results) {
		workers.Go(func() {
			<-start
			results <- VerifyPasswordGrantTotp(userID, invalid)
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var invalidResults int
	for err := range results {
		if errors.Is(err, ErrInvalidTotp) {
			invalidResults++
		} else {
			assert.ErrorIs(t, err, ErrTotpLocked)
		}
	}
	assert.Equal(t, maxTotpAttempts-1, invalidResults)
	var attempts int
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_failed_attempts FROM users WHERE id = ?`, userID).Scan(&attempts))
	assert.Equal(t, maxTotpAttempts, attempts)
}

// TestPasswordGrantTotpStorageFailure denies authentication when its state cannot persist.
func TestPasswordGrantTotpStorageFailure(t *testing.T) {
	userID, valid, _ := passwordGrantTotpUser(t)
	_, err := db.GetDB().Exec(`CREATE TRIGGER reject_totp_state BEFORE UPDATE ON users
		BEGIN SELECT RAISE(FAIL, 'injected TOTP state failure'); END`)
	require.NoError(t, err)
	err = VerifyPasswordGrantTotp(userID, valid)
	require.ErrorContains(t, err, "injected TOTP state failure")
	_, err = db.GetDB().Exec(`DROP TRIGGER reject_totp_state`)
	require.NoError(t, err)
	require.NoError(t, VerifyPasswordGrantTotp(userID, valid))
}

// TestPasswordGrantTotpNonpositiveCooldown retains a bounded policy when password lockout is disabled.
func TestPasswordGrantTotpNonpositiveCooldown(t *testing.T) {
	userID, _, invalid := passwordGrantTotpUser(t)
	config.Values.AuthAccountLockoutDuration = 0
	config.Values.AuthAccountLockoutMaxAttempts = 0
	for range maxTotpAttempts {
		require.Error(t, VerifyPasswordGrantTotp(userID, invalid))
	}
	var lockedUntil *time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_locked_until FROM users WHERE id = ?`, userID).Scan(&lockedUntil))
	require.NotNil(t, lockedUntil)
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), *lockedUntil, time.Second)
}
