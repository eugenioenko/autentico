package magiclink

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/cleanup"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// allowMagicLinkResend advances a fixture past the real request cooldown.
func allowMagicLinkResend(t *testing.T, hash string) {
	t.Helper()
	_, err := db.GetDB().Exec(`UPDATE magic_link_tokens SET created_at=? WHERE token_hash=?`, time.Now().UTC().Add(-2*time.Minute), hash)
	require.NoError(t, err)
}

// TestReplacementPreservesAccountBudgetAndExpiry carries failures across replacement and exhaustion.
func TestReplacementPreservesAccountBudgetAndExpiry(t *testing.T) {
	_, _, old := newCodeChallenge(t)
	for range 4 {
		_, err := recordFailedCodeAttempt(old)
		require.NoError(t, err)
	}
	_, originalExpiry, _, err := getMagicLinkTokenInfo(old)
	require.NoError(t, err)
	allowMagicLinkResend(t, old)
	expires, err := issueMagicLinkToken("attempt-user", "replacement", "code", time.Now().Add(2*time.Hour))
	require.NoError(t, err)
	require.True(t, expires.Equal(originalExpiry))
	var attempts int
	require.NoError(t, db.GetDB().QueryRow(`SELECT failed_attempts FROM magic_link_tokens WHERE token_hash='replacement'`).Scan(&attempts))
	require.Equal(t, 4, attempts)
	_, _, used, err := getMagicLinkTokenInfo(old)
	require.NoError(t, err)
	require.NotNil(t, used)
	attempts, err = recordFailedCodeAttempt("replacement")
	require.NoError(t, err)
	require.Equal(t, 5, attempts)
	require.ErrorIs(t, consumeMagicLinkToken("replacement"), sql.ErrNoRows)
	allowMagicLinkResend(t, "replacement")
	_, err = issueMagicLinkToken("attempt-user", "after-exhaustion", "code", time.Now().Add(time.Hour))
	require.ErrorIs(t, err, errIssuanceSuppressed, "a new request cannot clear the exhausted budget")
}

// TestReplacementCooldownPreservesCurrentCredential rejects duplicate requests before invalidation.
func TestReplacementCooldownPreservesCurrentCredential(t *testing.T) {
	_, _, hash := newCodeChallenge(t)
	_, err := issueMagicLinkToken("attempt-user", "too-soon", "code", time.Now().Add(time.Hour))
	require.ErrorIs(t, err, errIssuanceSuppressed)
	require.NoError(t, consumeMagicLinkToken(hash), "cooldown must not invalidate the email already sent")
}

// TestReplacementCarriesUsedBudgetAndResetsAfterExpiry bounds total failures during one window.
func TestReplacementCarriesUsedBudgetAndResetsAfterExpiry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			_, _, old := newCodeChallenge(t)
			_, err := recordFailedCodeAttempt(old)
			require.NoError(t, err)
			require.NoError(t, consumeMagicLinkToken(old))
			allowMagicLinkResend(t, old)
			if expired {
				_, err = db.GetDB().Exec(`UPDATE magic_link_tokens SET expires_at=? WHERE token_hash=?`, time.Now().Add(-time.Minute), old)
				require.NoError(t, err)
			}
			requested := time.Now().Add(time.Hour)
			actual, err := issueMagicLinkToken("attempt-user", "replacement", "code", requested)
			require.NoError(t, err)
			var attempts int
			require.NoError(t, db.GetDB().QueryRow(`SELECT failed_attempts FROM magic_link_tokens WHERE token_hash='replacement'`).Scan(&attempts))
			if expired {
				require.Zero(t, attempts)
				require.True(t, actual.Equal(requested))
			} else {
				require.Equal(t, 1, attempts)
			}
		})
	}
}

// TestConcurrentMagicLinkIssuanceSendsOneChallenge enforces the per-user cooldown atomically.
func TestConcurrentMagicLinkIssuanceSendsOneChallenge(t *testing.T) {
	withMagicLinkTestDB(t)
	testutils.InsertTestUser(t, "concurrent")
	start := make(chan struct{})
	results := make(chan error, 16)
	var workers sync.WaitGroup
	for i := range cap(results) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := issueMagicLinkToken("concurrent", fmt.Sprint("token-", i), "code", time.Now().Add(time.Hour))
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, errIssuanceSuppressed)
		}
	}
	require.Equal(t, 1, successes)
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM magic_link_tokens WHERE user_id='concurrent'`).Scan(&count))
	require.Equal(t, 1, count)
}

// TestIssuanceReadsBudgetAfterWriterAcquisition rejects failures committed while waiting for the writer.
func TestIssuanceReadsBudgetAfterWriterAcquisition(t *testing.T) {
	testutils.WithTotpKey(t)
	_, err := db.InitDB(filepath.Join(t.TempDir(), "auth.db"))
	require.NoError(t, err)
	t.Cleanup(db.CloseDB)
	testutils.InsertTestUser(t, "writer")
	require.NoError(t, createMagicLinkToken("writer", "old", "code", time.Now().Add(time.Hour)))
	allowMagicLinkResend(t, "old")
	conn, err := db.GetWriteDB().Conn(context.Background())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	waited := db.GetWriteDB().Stats().WaitCount
	result := make(chan error, 1)
	go func() {
		_, err := issueMagicLinkToken("writer", "replacement", "code", time.Now().Add(time.Hour))
		result <- err
	}()
	require.Eventually(t, func() bool { return db.GetWriteDB().Stats().WaitCount > waited }, 5*time.Second, time.Millisecond)
	_, err = conn.ExecContext(context.Background(), `UPDATE magic_link_tokens SET failed_attempts=5,used_at=CURRENT_TIMESTAMP WHERE token_hash='old'`)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.ErrorIs(t, <-result, errIssuanceSuppressed)
}

// TestIssuanceFailurePreservesOldLink rolls back invalidation on insert and deferred-commit failures.
func TestIssuanceFailurePreservesOldLink(t *testing.T) {
	for _, failure := range []string{"insert", "commit"} {
		t.Run(failure, func(t *testing.T) {
			_, _, old := newCodeChallenge(t)
			allowMagicLinkResend(t, old)
			trigger := `CREATE TRIGGER reject_issue BEFORE INSERT ON magic_link_tokens BEGIN SELECT RAISE(FAIL,'injected issuance failure'); END`
			if failure == "commit" {
				trigger = `CREATE TABLE issue_parent(id INTEGER PRIMARY KEY);CREATE TABLE issue_child(parent_id INTEGER REFERENCES issue_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER reject_issue AFTER INSERT ON magic_link_tokens BEGIN INSERT INTO issue_child VALUES(123); END`
			}
			_, err := db.GetDB().Exec(trigger)
			require.NoError(t, err)
			_, err = issueMagicLinkToken("attempt-user", "replacement", "code", time.Now().Add(time.Hour))
			require.Error(t, err)
			require.False(t, errors.Is(err, errIssuanceSuppressed))
			_, _, used, err := getMagicLinkTokenInfo(old)
			require.NoError(t, err)
			require.Nil(t, used)
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM magic_link_tokens WHERE token_hash='replacement'`).Scan(&count))
			require.Zero(t, count)
			_, err = db.GetDB().Exec(`DROP TRIGGER reject_issue`)
			require.NoError(t, err)
			require.NoError(t, consumeMagicLinkToken(old), "storage recovery must retain the original credential")
		})
	}
}

// TestCleanupPreservesLiveMagicLinkBudget checks the actual cleanup path across UTC offsets.
func TestCleanupPreservesLiveMagicLinkBudget(t *testing.T) {
	_, _, old := newCodeChallenge(t)
	allowMagicLinkResend(t, old)
	_, err := db.GetDB().Exec(`UPDATE magic_link_tokens SET expires_at=?,failed_attempts=5,used_at=CURRENT_TIMESTAMP WHERE token_hash=?`, time.Now().Add(time.Hour).In(time.FixedZone("PST", -12*60*60)), old)
	require.NoError(t, err)
	cleanup.Run(0)
	_, err = issueMagicLinkToken("attempt-user", "replacement", "code", time.Now().Add(time.Hour))
	require.ErrorIs(t, err, errIssuanceSuppressed, "cleanup must not erase a still-live guessing budget")
}
