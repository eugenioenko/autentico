package deletion

import (
	"net/http"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// TestImmediateDeletionRequiresPassword rejects stolen bearer credentials alone.
func TestImmediateDeletionRequiresPassword(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing", `{}`, 400}, {"wrong", `{"current_password":"wrong"}`, 403},
		{"malformed", `{"current_password":`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			_, usr, info := setupTestUserAndSession(t)
			setDeletionPassword(t, usr)
			testutils.WithConfigOverride(t, func() { config.Values.AllowSelfServiceDeletion = true; config.Values.AuditLogRetentionStr = "24h" })
			rr := mockAuthRequest(t, tc.body, http.MethodPost, "/account/api/deletion-request", HandleRequestDeletion, info)
			require.Equal(t, tc.status, rr.Code)
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM users WHERE id=?`, usr.ID).Scan(&count))
			require.Equal(t, 1, count)
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND deactivated_at IS NULL`, usr.ID).Scan(&count))
			require.Equal(t, 1, count)
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE event='user_deleted'`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

// TestImmediateDeletionAuditsActor preserves attribution after the account is removed.
func TestImmediateDeletionAuditsActor(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)
	setDeletionPassword(t, usr)
	testutils.WithConfigOverride(t, func() { config.Values.AllowSelfServiceDeletion = true; config.Values.AuditLogRetentionStr = "24h" })
	rr := mockAuthRequest(t, `{"current_password":"Password123!","reason":"done"}`, http.MethodPost, "/account/api/deletion-request", HandleRequestDeletion, info)
	require.Equal(t, 204, rr.Code)
	var actor, name, target, detail string
	require.NoError(t, db.GetDB().QueryRow(`SELECT actor_id,actor_username,target_id,detail FROM audit_logs WHERE event='user_deleted'`).Scan(&actor, &name, &target, &detail))
	require.Equal(t, usr.ID, actor)
	require.Equal(t, usr.Username, name)
	require.Equal(t, usr.ID, target)
	require.JSONEq(t, `{"source":"self"}`, detail)
	require.NotContains(t, detail, "Password123!")
}

// TestPasswordlessDeletionRequiresAdminReview never treats an absent password as proof.
func TestPasswordlessDeletionRequiresAdminReview(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)
	_, err := db.GetDB().Exec(`UPDATE users SET password=NULL WHERE id=?`, usr.ID)
	require.NoError(t, err)
	usr.Password = ""
	testutils.WithConfigOverride(t, func() { config.Values.AllowSelfServiceDeletion = true })
	rr := mockAuthRequest(t, `{"reason":"please remove","current_password":"arbitrary"}`, http.MethodPost, "/account/api/deletion-request", HandleRequestDeletion, info)
	require.Equal(t, 201, rr.Code)
	pending, err := DeletionRequestByUserID(usr.ID)
	require.NoError(t, err)
	require.NotNil(t, pending)
	require.Equal(t, "please remove", pending.Reason.String)
	var users int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM users WHERE id=?`, usr.ID).Scan(&users))
	require.Equal(t, 1, users)
}

// TestDeletionPasswordLockout uses the account's existing password attempt budget.
func TestDeletionPasswordLockout(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)
	setDeletionPassword(t, usr)
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowSelfServiceDeletion = true
		config.Values.AuthAccountLockoutMaxAttempts = 2
		config.Values.AuthAccountLockoutDuration = time.Minute
	})
	for i := 0; i < 2; i++ {
		rr := mockAuthRequest(t, `{"current_password":"wrong"}`, http.MethodPost, "/account/api/deletion-request", HandleRequestDeletion, info)
		require.Equal(t, 403, rr.Code)
	}
	rr := mockAuthRequest(t, `{"current_password":"Password123!"}`, http.MethodPost, "/account/api/deletion-request", HandleRequestDeletion, info)
	require.Equal(t, 429, rr.Code)
	require.Contains(t, rr.Body.String(), "account_locked")
}
