package passwordreset

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func postReset(raw, password string) *httptest.ResponseRecorder {
	form := url.Values{"token": {raw}, "password": {password}, "confirm_password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleResetPassword(rr, req)
	return rr
}

func TestResetFailureLeavesPasswordTokenAndSessionsUnchanged(t *testing.T) {
	for _, stage := range []string{"token", "password", "sessions", "idp", "commit"} {
		t.Run(stage, func(t *testing.T) {
			testutils.WithTestDB(t)
			usr, err := user.CreateUser("atomic-reset", "OldPassword123!", "reset@example.com")
			require.NoError(t, err)
			var originalPassword string
			require.NoError(t, db.GetDB().QueryRow(`SELECT password FROM users WHERE id=?`, usr.ID).Scan(&originalPassword))
			raw, hash, err := generateToken()
			require.NoError(t, err)
			require.NoError(t, createResetToken(usr.ID, hash, time.Now().Add(time.Hour)))
			_, err = db.GetDB().Exec(`INSERT INTO sessions(id,user_id) VALUES('reset-session',?);
				INSERT INTO idp_sessions(id,user_id) VALUES('reset-idp',?)`, usr.ID, usr.ID)
			require.NoError(t, err)
			if stage == "commit" {
				_, err = db.GetDB().Exec(`CREATE TABLE reset_parent(id INTEGER PRIMARY KEY);
					CREATE TABLE reset_deferred(id INTEGER REFERENCES reset_parent(id) DEFERRABLE INITIALLY DEFERRED);
					CREATE TRIGGER fail_reset AFTER UPDATE OF password ON users BEGIN INSERT INTO reset_deferred VALUES(1); END`)
			} else {
				clauses := map[string]string{"token": "used_at ON password_reset_tokens", "password": "password ON users", "sessions": "deactivated_at ON sessions", "idp": "deactivated_at ON idp_sessions"}
				_, err = db.GetDB().Exec(fmt.Sprintf(`CREATE TRIGGER fail_reset BEFORE UPDATE OF %s BEGIN SELECT RAISE(ABORT,'injected reset failure'); END`, clauses[stage]))
			}
			require.NoError(t, err)
			rr := postReset(raw, "NewPassword456!")
			require.NotContains(t, rr.Body.String(), "reset successfully")
			var password string
			require.NoError(t, db.GetDB().QueryRow(`SELECT password FROM users WHERE id=?`, usr.ID).Scan(&password))
			require.Equal(t, originalPassword, password)
			_, _, usedAt, err := getResetTokenInfo(hash)
			require.NoError(t, err)
			require.Nil(t, usedAt)
			for _, table := range []string{"sessions", "idp_sessions"} {
				var active int
				require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table+" WHERE user_id=? AND deactivated_at IS NULL", usr.ID).Scan(&active))
				require.Equal(t, 1, active, table)
			}
			_, err = db.GetDB().Exec(`DROP TRIGGER fail_reset`)
			require.NoError(t, err)
			require.Contains(t, postReset(raw, "NewPassword456!").Body.String(), "reset successfully", "the same token must remain usable after rollback")
			_, _, usedAt, err = getResetTokenInfo(hash)
			require.NoError(t, err)
			require.NotNil(t, usedAt)
			for _, table := range []string{"sessions", "idp_sessions"} {
				var active int
				require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table+" WHERE user_id=? AND deactivated_at IS NULL", usr.ID).Scan(&active))
				require.Zero(t, active, table)
			}
		})
	}
}

func TestConcurrentPasswordResetHasOneWinner(t *testing.T) {
	testutils.WithTestDB(t)
	usr, err := user.CreateUser("racing-reset", "OldPassword123!", "race@example.com")
	require.NoError(t, err)
	raw, hash, err := generateToken()
	require.NoError(t, err)
	require.NoError(t, createResetToken(usr.ID, hash, time.Now().Add(time.Hour)))
	start := make(chan struct{})
	results := make(chan int, 20)
	var workers sync.WaitGroup
	for i := range cap(results) {
		workers.Go(func() {
			<-start
			if strings.Contains(postReset(raw, fmt.Sprintf("NewPassword%d!", i)).Body.String(), "reset successfully") {
				results <- i
			} else {
				results <- -1
			}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	winner := -1
	for won := range results {
		if won >= 0 {
			winners++
			winner = won
		}
	}
	require.Equal(t, 1, winners)
	var storedPassword string
	require.NoError(t, db.GetDB().QueryRow(`SELECT password FROM users WHERE id=?`, usr.ID).Scan(&storedPassword))
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(fmt.Sprintf("NewPassword%d!", winner))), "losers must not overwrite the winning password")
}

func TestResetRechecksEligibilityInsideTransaction(t *testing.T) {
	for _, state := range []string{"expired", "deactivated"} {
		t.Run(state, func(t *testing.T) {
			testutils.WithTestDB(t)
			usr, err := user.CreateUser("ineligible-reset", "OldPassword123!", "reset@example.com")
			require.NoError(t, err)
			_, hash, err := generateToken()
			require.NoError(t, err)
			require.NoError(t, createResetToken(usr.ID, hash, time.Now().Add(time.Hour)))
			query := "UPDATE password_reset_tokens SET expires_at=datetime('now','-1 minute') WHERE token_hash=?"
			arg := hash
			if state == "deactivated" {
				query, arg = "UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id=?", usr.ID
			}
			_, err = db.GetDB().Exec(query, arg)
			require.NoError(t, err)
			require.ErrorIs(t, resetPassword(context.Background(), hash, "NewPassword123!"), errResetUnavailable)
			_, _, usedAt, err := getResetTokenInfo(hash)
			require.NoError(t, err)
			require.Nil(t, usedAt)
			var stored string
			require.NoError(t, db.GetDB().QueryRow("SELECT password FROM users WHERE id=?", usr.ID).Scan(&stored))
			require.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored), []byte("OldPassword123!")))
		})
	}
}
