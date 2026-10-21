package magiclink

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyURLRequest exercises URL redemption with the same signed parameters as the code path.
func verifyURLRequest(form url.Values, raw string) *httptest.ResponseRecorder {
	query := url.Values{}
	for key, values := range form {
		query[key] = append([]string(nil), values...)
	}
	query.Set("token", raw)
	rr := httptest.NewRecorder()
	HandleMagicLinkVerify(rr, httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?"+query.Encode(), nil))
	return rr
}

// TestMagicLinkConsumptionConcurrentStaleReads forces every contender to observe an unused token first.
func TestMagicLinkConsumptionConcurrentStaleReads(t *testing.T) {
	_, _, hash := newCodeChallenge(t)
	const contenders = 16
	ready := make(chan error, contenders)
	results := make(chan error, contenders)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range contenders {
		workers.Go(func() {
			_, _, used, err := getMagicLinkTokenInfo(hash)
			if err == nil && used != nil {
				err = sql.ErrNoRows
			}
			ready <- err
			<-start
			results <- consumeMagicLinkToken(hash)
		})
	}
	// Release all workers even if a setup assertion fails.
	for range contenders {
		assert.NoError(t, <-ready)
	}
	close(start)
	workers.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		} else {
			assert.ErrorIs(t, err, sql.ErrNoRows)
		}
	}
	assert.Equal(t, 1, successes)
}

// TestMagicLinkConsumptionConcurrentURLAndCode permits only one authentication across both paths.
func TestMagicLinkConsumptionConcurrentURLAndCode(t *testing.T) {
	form, raw, _ := newCodeChallenge(t)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 12)
	var workers sync.WaitGroup
	for i := range cap(results) {
		workers.Go(func() {
			<-start
			if i%2 == 0 {
				results <- verifyURLRequest(form, raw)
			} else {
				results <- verifyCodeRequest(form)
			}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var successes int
	for rr := range results {
		if rr.Code == http.StatusFound {
			successes++
			assert.Contains(t, rr.Header().Get("Location"), "code=")
		} else {
			assert.Empty(t, rr.Header().Get("Location"))
		}
	}
	assert.Equal(t, 1, successes)
	var codes int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes WHERE user_id = 'attempt-user'`).Scan(&codes))
	assert.Equal(t, 1, codes)
}

// TestMagicLinkConsumptionFailureBlocksLogin verifies both paths abort when consumption cannot persist.
func TestMagicLinkConsumptionFailureBlocksLogin(t *testing.T) {
	for _, path := range []string{"url", "code"} {
		t.Run(path, func(t *testing.T) {
			form, raw, hash := newCodeChallenge(t)
			_, err := db.GetDB().Exec(`CREATE TRIGGER reject_consumption BEFORE UPDATE ON magic_link_tokens
				BEGIN SELECT RAISE(FAIL, 'injected consumption failure'); END`)
			require.NoError(t, err)
			verify := func() *httptest.ResponseRecorder {
				if path == "url" {
					return verifyURLRequest(form, raw)
				}
				return verifyCodeRequest(form)
			}
			for range 2 {
				rr := verify()
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.Empty(t, rr.Header().Get("Location"))
			}
			var codes int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes WHERE user_id = 'attempt-user'`).Scan(&codes))
			assert.Zero(t, codes)
			_, _, used, err := getMagicLinkTokenInfo(hash)
			require.NoError(t, err)
			assert.Nil(t, used)
			_, err = db.GetDB().Exec(`DROP TRIGGER reject_consumption`)
			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, verify().Code, "a failed consumption must be retryable after storage recovers")
		})
	}
}

// TestMagicLinkConsumptionEligibility rechecks expiry and attempt limits after any stale handler read.
func TestMagicLinkConsumptionEligibility(t *testing.T) {
	for _, state := range []string{"expired", "exhausted", "valid-other-offset"} {
		t.Run(state, func(t *testing.T) {
			_, _, hash := newCodeChallenge(t)
			switch state {
			case "expired":
				// This expired instant has a wall clock ahead of local time.
				expires := time.Now().Add(-time.Minute).In(time.FixedZone("FUT", 14*60*60))
				_, err := db.GetDB().Exec(`UPDATE magic_link_tokens SET expires_at = ? WHERE token_hash = ?`, expires, hash)
				require.NoError(t, err)
			case "exhausted":
				_, err := db.GetDB().Exec(`UPDATE magic_link_tokens SET failed_attempts = ? WHERE token_hash = ?`, maxCodeAttempts, hash)
				require.NoError(t, err)
			case "valid-other-offset":
				expires := time.Now().Add(time.Hour).In(time.FixedZone("PST", -12*60*60))
				_, err := db.GetDB().Exec(`UPDATE magic_link_tokens SET expires_at = ? WHERE token_hash = ?`, expires, hash)
				require.NoError(t, err)
			}
			err := consumeMagicLinkToken(hash)
			_, _, used, readErr := getMagicLinkTokenInfo(hash)
			require.NoError(t, readErr)
			if state == "valid-other-offset" {
				require.NoError(t, err)
				assert.NotNil(t, used)
			} else {
				assert.ErrorIs(t, err, sql.ErrNoRows)
				assert.Nil(t, used, "an ineligible claim must roll back")
			}
		})
	}
}

// TestMagicLinkConsumptionCommitFailure rolls back a claim when COMMIT rejects a deferred constraint.
func TestMagicLinkConsumptionCommitFailure(t *testing.T) {
	_, _, hash := newCodeChallenge(t)
	_, err := db.GetDB().Exec(`CREATE TABLE consume_parent (id INTEGER PRIMARY KEY);
		CREATE TABLE consume_child (parent_id INTEGER REFERENCES consume_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER reject_consumption AFTER UPDATE ON magic_link_tokens
		BEGIN INSERT INTO consume_child VALUES (123); END`)
	require.NoError(t, err)
	err = consumeMagicLinkToken(hash)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FOREIGN KEY")
	_, _, used, err := getMagicLinkTokenInfo(hash)
	require.NoError(t, err)
	assert.Nil(t, used)
	var children int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM consume_child`).Scan(&children))
	assert.Zero(t, children)
	_, err = db.GetDB().Exec(`DROP TRIGGER reject_consumption`)
	require.NoError(t, err)
	require.NoError(t, consumeMagicLinkToken(hash), "the connection and token must remain usable after recovery")
}
