package mfa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func atomicEmailChallenge(t *testing.T) {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.TrustDeviceEnabled = true })
	testutils.InsertTestUser(t, "atomic-mfa")
	testutils.InsertTestClient(t, "atomic-client", []string{"http://localhost/cb"})
	require.NoError(t, CreateMfaChallenge(MfaChallenge{ID: "atomic-challenge", UserID: "atomic-mfa", Method: "email",
		Code: utils.HashSHA256("123456"), ExpiresAt: time.Now().Add(time.Minute),
		LoginState: `{"client_id":"atomic-client","redirect_uri":"http://localhost/cb","scope":"openid"}`}))
}

func postAtomicMfa() *httptest.ResponseRecorder {
	form := url.Values{"challenge_id": {"atomic-challenge"}, "code": {"123456"}, "trust_device": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)
	return rr
}

func TestMfaChallengeConsumptionFailureIssuesNoAuthenticatedState(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		t.Run(map[bool]string{false: "write failure", true: "exhausted"}[exhausted], func(t *testing.T) {
			atomicEmailChallenge(t)
			var err error
			if exhausted {
				_, err = db.GetDB().Exec(`UPDATE mfa_challenges SET failed_attempts=5 WHERE id='atomic-challenge'`)
			} else {
				_, err = db.GetDB().Exec(`CREATE TRIGGER fail_challenge BEFORE UPDATE OF used ON mfa_challenges
					WHEN NEW.used=TRUE BEGIN SELECT RAISE(ABORT,'injected challenge failure'); END`)
			}
			require.NoError(t, err)
			rr := postAtomicMfa()
			require.NotContains(t, rr.Header().Get("Location"), "http://localhost/cb")
			require.Empty(t, rr.Result().Cookies())
			for _, table := range []string{"auth_codes", "idp_sessions", "trusted_devices"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count))
				require.Zero(t, count, table)
			}
		})
	}
}

func TestConcurrentEmailMfaChallengeHasOneWinner(t *testing.T) {
	atomicEmailChallenge(t)
	start := make(chan struct{})
	results := make(chan bool, 20)
	var workers sync.WaitGroup
	for range cap(results) {
		workers.Go(func() {
			<-start
			results <- strings.HasPrefix(postAtomicMfa().Header().Get("Location"), "http://localhost/cb")
		})
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for won := range results {
		if won {
			winners++
		}
	}
	require.Equal(t, 1, winners)
	var codes int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&codes))
	require.Equal(t, 1, codes)
}

func TestConsumeMfaChallengeRejectsChangedOrIneligibleState(t *testing.T) {
	for _, mutation := range []string{"used", "expired", "exhausted", "code", "method", "user", "login state"} {
		t.Run(mutation, func(t *testing.T) {
			atomicEmailChallenge(t)
			snapshot, err := MfaChallengeByIDIncludingExpired("atomic-challenge")
			require.NoError(t, err)
			testutils.InsertTestUser(t, "other-user")
			queries := map[string]string{
				"used": "used=TRUE", "expired": "expires_at=datetime('now','-1 minute')", "exhausted": "failed_attempts=5",
				"code": "code='different-hash'", "method": "method='totp'", "user": "user_id='other-user'", "login state": "login_state='{}'",
			}
			_, err = db.GetDB().Exec("UPDATE mfa_challenges SET " + queries[mutation] + " WHERE id='atomic-challenge'")
			require.NoError(t, err)
			require.ErrorIs(t, ConsumeMfaChallenge(context.Background(), *snapshot), ErrChallengeUnavailable)
			current, err := MfaChallengeByIDIncludingExpired("atomic-challenge")
			require.NoError(t, err)
			require.Equal(t, mutation == "used", current.Used, "a rejected claim must not consume the challenge")
		})
	}
}

func TestMfaChallengeCommitFailureRollsBackAndCanRetry(t *testing.T) {
	atomicEmailChallenge(t)
	_, err := db.GetDB().Exec(`CREATE TABLE challenge_parent(id INTEGER PRIMARY KEY);
		CREATE TABLE challenge_deferred(id INTEGER REFERENCES challenge_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_challenge AFTER UPDATE OF used ON mfa_challenges
		WHEN NEW.used=TRUE BEGIN INSERT INTO challenge_deferred VALUES(1); END`)
	require.NoError(t, err)
	rr := postAtomicMfa()
	require.NotContains(t, rr.Header().Get("Location"), "http://localhost/cb")
	require.Empty(t, rr.Result().Cookies())
	current, err := MfaChallengeByIDIncludingExpired("atomic-challenge")
	require.NoError(t, err)
	require.False(t, current.Used)
	for _, table := range []string{"auth_codes", "idp_sessions", "trusted_devices", "challenge_deferred"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
	_, err = db.GetDB().Exec(`DROP TRIGGER fail_challenge`)
	require.NoError(t, err)
	require.Contains(t, postAtomicMfa().Header().Get("Location"), "http://localhost/cb", "the writer and challenge must remain usable after failed COMMIT")
}
