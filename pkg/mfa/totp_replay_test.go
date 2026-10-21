package mfa

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

const replaySecret = "JBSWY3DPEHPK3PXP"

var replayTime = time.Unix(1800000005, 0)

func TestTotpReplaySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "totp-replay.db")
	_, err := db.InitDB(path)
	require.NoError(t, err)
	t.Cleanup(db.CloseDB)
	testutils.InsertTestUser(t, "persistent-replay")
	require.NoError(t, user.SaveTotpSecret("persistent-replay", replaySecret))
	code := replayCode(t, replayTime)
	require.NoError(t, consumeTotpCodeAt("persistent-replay", replaySecret, code, replayTime))
	db.CloseDB()
	_, err = db.InitDB(path)
	require.NoError(t, err)
	require.ErrorIs(t, consumeTotpCodeAt("persistent-replay", replaySecret, code, replayTime), ErrInvalidTotp)
}

func replayUser(t *testing.T) string {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "replay-user")
	require.NoError(t, user.SaveTotpSecret("replay-user", replaySecret))
	return "replay-user"
}

func replayCode(t *testing.T, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(replaySecret, at)
	require.NoError(t, err)
	return code
}

func TestTotpReplayAndClockSkew(t *testing.T) {
	for _, offset := range []int{-2, -1, 0, 1, 2} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			id := replayUser(t)
			code := replayCode(t, replayTime.Add(time.Duration(offset)*30*time.Second))
			err := consumeTotpCodeAt(id, replaySecret, code, replayTime)
			if offset < -1 || offset > 1 {
				require.ErrorIs(t, err, ErrInvalidTotp)
				return
			}
			require.NoError(t, err)
			require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, replayTime), ErrInvalidTotp)
			var accepted int64
			require.NoError(t, db.GetDB().QueryRow("SELECT totp_last_used_step FROM users WHERE id=?", id).Scan(&accepted))
			require.Equal(t, replayTime.Unix()/30+int64(offset), accepted)
			// A new challenge or subsequent receive window must not make the code reusable.
			require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, replayTime.Add(30*time.Second)), ErrInvalidTotp)
		})
	}
}

func TestTotpReplayAcrossVerificationPaths(t *testing.T) {
	for _, passwordFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(passwordFirst), func(t *testing.T) {
			id := replayUser(t)
			code := replayCode(t, replayTime)
			if passwordFirst {
				require.NoError(t, verifyPasswordGrantTotpAt(id, code, replayTime))
				require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, replayTime), ErrInvalidTotp)
			} else {
				require.NoError(t, consumeTotpCodeAt(id, replaySecret, code, replayTime))
				require.ErrorIs(t, verifyPasswordGrantTotpAt(id, code, replayTime), ErrInvalidTotp)
			}
			next := replayTime.Add(30 * time.Second)
			require.NoError(t, verifyPasswordGrantTotpAt(id, replayCode(t, next), next))
			require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, next), ErrInvalidTotp)
		})
	}
}

func TestTotpReplayCollisionAcrossOverlappingWindows(t *testing.T) {
	// Independent RFC 4226 vector: this seed produces 945099 at both steps.
	const code = "945099"
	first := time.Unix(61831282*30+5, 0)
	second := time.Unix(61831284*30+5, 0)
	for _, passwordFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(passwordFirst), func(t *testing.T) {
			id := replayUser(t)
			if passwordFirst {
				require.NoError(t, verifyPasswordGrantTotpAt(id, code, first))
				require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, second), ErrInvalidTotp)
			} else {
				require.NoError(t, consumeTotpCodeAt(id, replaySecret, code, first))
				require.ErrorIs(t, verifyPasswordGrantTotpAt(id, code, second), ErrInvalidTotp)
			}
			var used int64
			require.NoError(t, db.GetDB().QueryRow("SELECT totp_last_used_step FROM users WHERE id=?", id).Scan(&used))
			require.Equal(t, int64(61831283), used)
		})
	}
}

func TestTotpConcurrentReplayAcrossPaths(t *testing.T) {
	id := replayUser(t)
	code := replayCode(t, replayTime)
	results := make(chan error, 20)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := range cap(results) {
		workers.Go(func() {
			<-start
			if i%2 == 0 {
				results <- consumeTotpCodeAt(id, replaySecret, code, replayTime)
			} else {
				results <- verifyPasswordGrantTotpAt(id, code, replayTime)
			}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.True(t, errors.Is(err, ErrInvalidTotp) || errors.Is(err, ErrTotpLocked), "%v", err)
		}
	}
	require.Equal(t, 1, successes)
}

func TestTotpConcurrentEnrollmentConfirmation(t *testing.T) {
	id := replayUser(t)
	require.NoError(t, user.DisableMfa(id))
	require.NoError(t, user.StoreTotpSecretPending(id, replaySecret))
	current, err := user.UserByID(id)
	require.NoError(t, err)
	code := replayCode(t, time.Now())
	results := make(chan error, 10)
	var workers sync.WaitGroup
	for range cap(results) {
		workers.Go(func() { results <- ConfirmTotpEnrollment(current.ID, replaySecret, code) })
	}
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, ErrInvalidTotp)
		}
	}
	require.Equal(t, 1, successes)
}

func TestTotpReplayStorageFailureDoesNotConsume(t *testing.T) {
	id := replayUser(t)
	code := replayCode(t, replayTime)
	_, err := db.GetDB().Exec(`CREATE TRIGGER fail_replay BEFORE UPDATE ON users BEGIN SELECT RAISE(FAIL,'injected replay write failure'); END`)
	require.NoError(t, err)
	require.ErrorContains(t, consumeTotpCodeAt(id, replaySecret, code, replayTime), "injected replay write failure")
	_, err = db.GetDB().Exec("DROP TRIGGER fail_replay")
	require.NoError(t, err)
	require.NoError(t, consumeTotpCodeAt(id, replaySecret, code, replayTime))
}

func TestTotpReplayBoundToActiveEnrollment(t *testing.T) {
	id := replayUser(t)
	code := replayCode(t, replayTime)
	for _, state := range []string{"totp_verified=FALSE", "totp_secret='different-secret'", "deactivated_at=CURRENT_TIMESTAMP"} {
		_, err := db.GetDB().Exec("UPDATE users SET "+state+" WHERE id=?", id)
		require.NoError(t, err)
		require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, replayTime), ErrInvalidTotp)
		_, err = db.GetDB().Exec("UPDATE users SET totp_verified=TRUE,totp_secret=?,deactivated_at=NULL WHERE id=?", replaySecret, id)
		require.NoError(t, err)
	}
	require.NoError(t, consumeTotpCodeAt(id, replaySecret, code, replayTime))
	// Re-saving the same seed and unlocking the account must not reset replay state.
	require.NoError(t, user.SaveTotpSecret(id, replaySecret))
	require.NoError(t, user.UnlockUser(id))
	require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, replayTime), ErrInvalidTotp)
	// A stale setup request cannot replace an active enrollment or its watermark.
	require.Error(t, user.StoreTotpSecretPending(id, "new-secret"))
	require.ErrorIs(t, consumeTotpCodeAt(id, replaySecret, code, replayTime), ErrInvalidTotp)
}

func TestTotpEnrollmentConfirmationConsumesCode(t *testing.T) {
	id := replayUser(t)
	require.NoError(t, user.DisableMfa(id))
	require.NoError(t, user.StoreTotpSecretPending(id, replaySecret))
	current, err := user.UserByID(id)
	require.NoError(t, err)
	code := replayCode(t, time.Now())
	require.NoError(t, ConfirmTotpEnrollment(current.ID, replaySecret, code))
	require.ErrorIs(t, ConfirmTotpEnrollment(current.ID, replaySecret, code), ErrInvalidTotp)
	require.ErrorIs(t, ConsumeTotpCode(id, replaySecret, code), ErrInvalidTotp)
	require.ErrorIs(t, VerifyPasswordGrantTotp(id, code), ErrInvalidTotp)
	// A replacement enrollment has independent replay state and must prove its new seed.
	require.NoError(t, user.DisableMfa(id))
	newSecret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	require.NoError(t, user.StoreTotpSecretPending(id, newSecret))
	require.ErrorIs(t, ConfirmTotpEnrollment(current.ID, replaySecret, code), ErrInvalidTotp)
	current, err = user.UserByID(id)
	require.NoError(t, err)
	newCode, err := totp.GenerateCode(newSecret, time.Now())
	require.NoError(t, err)
	require.NoError(t, ConfirmTotpEnrollment(current.ID, newSecret, newCode))
}
