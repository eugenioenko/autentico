package user_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/passwordreset"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// confirmedDeletion creates a live caller and an opaque password confirmation.
func confirmedDeletion(t *testing.T) (user.PasswordConfirmation, string, string) {
	t.Helper()
	usr, err := user.CreateUser("delete-confirmation", "Password123!", "confirmation@test.com")
	require.NoError(t, err)
	access := "confirmed-caller"
	_, err = db.GetDB().Exec(`INSERT INTO tokens(id,user_id,access_token_hash,refresh_token_hash,access_token_type,access_token_expires_at,refresh_token_expires_at,scope,grant_type) VALUES('token',?,?,'refresh','Bearer',datetime('now','+1 hour'),datetime('now','+2 hours'),'openid profile email','password')`, usr.ID, utils.HashToken(access))
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`INSERT INTO sessions(id,user_id,access_token_hash) VALUES('caller',?,?)`, usr.ID, utils.HashToken(access))
	require.NoError(t, err)
	proof, err := user.ConfirmPassword(usr.ID, "Password123!")
	require.NoError(t, err)
	return proof, access, usr.ID
}

// TestConfirmedDeletionRejectsChangedState checks mutations committed after password confirmation.
func TestConfirmedDeletionRejectsChangedState(t *testing.T) {
	for _, change := range []string{"password", "deactivation", "session", "token", "expiry", "session owner", "token owner"} {
		t.Run(change, func(t *testing.T) {
			testutils.WithTestDB(t)
			proof, access, id := confirmedDeletion(t)
			testutils.InsertTestUser(t, "other")
			query := map[string]string{
				"password":      `UPDATE users SET password='replacement' WHERE id=?`,
				"deactivation":  `UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id=?`,
				"session":       `UPDATE sessions SET deactivated_at=CURRENT_TIMESTAMP WHERE user_id=?`,
				"token":         `UPDATE tokens SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=?`,
				"expiry":        `UPDATE tokens SET access_token_expires_at=datetime('now','-1 second') WHERE user_id=?`,
				"session owner": `UPDATE sessions SET user_id='other' WHERE user_id=?`,
				"token owner":   `UPDATE tokens SET user_id='other' WHERE user_id=?`,
			}[change]
			_, err := db.GetDB().Exec(query, id)
			require.NoError(t, err)
			require.ErrorIs(t, user.HardDeleteConfirmedUser(proof, access, "caller"), user.ErrDeletionAuthorizationChanged)
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM users WHERE id=?`, id).Scan(&count))
			require.Equal(t, 1, count)
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions WHERE id='caller'`).Scan(&count))
			require.Equal(t, 1, count)
		})
	}
}

// TestPasswordResetInvalidatesPendingDeletion executes the real reset between confirmation and deletion.
func TestPasswordResetInvalidatesPendingDeletion(t *testing.T) {
	testutils.WithTestDB(t)
	proof, access, id := confirmedDeletion(t)
	_, err := db.GetDB().Exec(`INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES('reset',?,?,?)`, id, utils.HashSHA256("reset-secret"), time.Now().Add(time.Hour))
	require.NoError(t, err)
	form := url.Values{"token": {"reset-secret"}, "password": {"NewPassword123!"}, "confirm_password": {"NewPassword123!"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	passwordreset.HandleResetPassword(rr, req)
	require.Less(t, rr.Code, 400)
	require.NoError(t, user.VerifyPassword(id, "NewPassword123!"), "reset must have committed")
	require.ErrorIs(t, user.HardDeleteConfirmedUser(proof, access, "caller"), user.ErrDeletionAuthorizationChanged)
	require.NoError(t, user.VerifyPassword(id, "NewPassword123!"), "stale deletion preserves reset credentials")
}

// TestConfirmedDeletionSucceedsOnce checks live credentials and rejects proof reuse.
func TestConfirmedDeletionSucceedsOnce(t *testing.T) {
	testutils.WithTestDB(t)
	proof, access, id := confirmedDeletion(t)
	require.NoError(t, user.HardDeleteConfirmedUser(proof, access, "caller"))
	require.ErrorIs(t, user.HardDeleteConfirmedUser(proof, access, "caller"), user.ErrDeletionAuthorizationChanged)
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM users WHERE id=?`, id).Scan(&count))
	require.Zero(t, count)
}
