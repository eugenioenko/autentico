package user

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestConcurrentPasswordFailuresUseCurrentBudget accounts for all guesses from one shared snapshot.
func TestConcurrentPasswordFailuresUseCurrentBudget(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 5
		config.Values.AuthAccountLockoutDuration = time.Minute
	})
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	require.NoError(t, err)
	testutils.InsertTestUser(t, "budget")
	_, err = db.GetDB().Exec(`UPDATE users SET password=? WHERE id='budget'`, string(hash))
	require.NoError(t, err)
	snapshot, err := UserByID("budget")
	require.NoError(t, err)
	results := make(chan error, 20)
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() { defer group.Done(); <-start; results <- verifyPasswordWithLockout(snapshot, "wrong") }()
	}
	close(start)
	group.Wait()
	close(results)
	locked, failed := 0, 0
	for err := range results {
		require.Error(t, err)
		if errors.Is(err, ErrAccountLocked) {
			locked++
		} else {
			failed++
		}
	}
	require.Equal(t, 5, failed)
	require.Equal(t, 15, locked)
	current, err := UserByID("budget")
	require.NoError(t, err)
	require.Equal(t, 5, current.FailedLoginAttempts)
	require.NotNil(t, current.LockedUntil)
	require.True(t, current.LockedUntil.After(time.Now()))
	require.ErrorIs(t, verifyPasswordWithLockout(snapshot, "correct"), ErrAccountLocked, "a stale unlocked snapshot cannot bypass the current lock")
}

// TestPasswordVerificationRejectsChangedSnapshot prevents stale bcrypt results authorizing a reset account.
func TestPasswordVerificationRejectsChangedSnapshot(t *testing.T) {
	for _, change := range []string{"password", "deactivation"} {
		t.Run(change, func(t *testing.T) {
			testutils.WithTestDB(t)
			hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
			require.NoError(t, err)
			testutils.InsertTestUser(t, "changed")
			_, err = db.GetDB().Exec(`UPDATE users SET password=? WHERE id='changed'`, string(hash))
			require.NoError(t, err)
			snapshot, err := UserByID("changed")
			require.NoError(t, err)
			query := `UPDATE users SET password='replacement' WHERE id='changed'`
			if change == "deactivation" {
				query = `UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id='changed'`
			}
			_, err = db.GetDB().Exec(query)
			require.NoError(t, err)
			require.Error(t, verifyPasswordWithLockout(snapshot, "correct"))
		})
	}
}
