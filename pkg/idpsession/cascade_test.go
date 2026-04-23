package idpsession

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertSession writes an active sessions row tied to the given idp_session_id.
// Empty idp_session_id stores SQL NULL (the untethered rows cascade must skip).
func insertSession(t *testing.T, id, userID, idpSessionID, accessToken string) {
	t.Helper()
	var idp interface{}
	if idpSessionID != "" {
		idp = idpSessionID
	}
	_, err := db.GetDB().Exec(
		`INSERT INTO sessions (id, user_id, access_token, refresh_token, expires_at, idp_session_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, accessToken, accessToken+"-refresh", time.Now().Add(time.Hour), idp,
	)
	require.NoError(t, err)
}

// insertToken writes an active tokens row for the given access_token.
func insertToken(t *testing.T, id, userID, accessToken string) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, accessToken, accessToken+"-refresh", "Bearer",
		time.Now().Add(24*time.Hour), time.Now().Add(time.Hour),
		time.Now(), "openid", "authorization_code",
	)
	require.NoError(t, err)
}

func TestDeactivateWithCascade_DeactivatesIdpSessionChildSessionsAndTokens(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	// Target IdP session with two child OAuth sessions (e.g. 2 apps signed in).
	require.NoError(t, CreateIdpSession(IdpSession{
		ID: "idp-target", UserID: "user-1", UserAgent: "ua", IPAddress: "127.0.0.1",
	}))
	insertSession(t, "sess-1", "user-1", "idp-target", "at-1")
	insertSession(t, "sess-2", "user-1", "idp-target", "at-2")
	insertToken(t, "tok-1", "user-1", "at-1")
	insertToken(t, "tok-2", "user-1", "at-2")

	// Unrelated IdP session on the same user must survive.
	require.NoError(t, CreateIdpSession(IdpSession{
		ID: "idp-other", UserID: "user-1", UserAgent: "ua", IPAddress: "127.0.0.1",
	}))
	insertSession(t, "sess-other", "user-1", "idp-other", "at-other")
	insertToken(t, "tok-other", "user-1", "at-other")

	// Unlinked session (e.g. ROPC/client_credentials) — NULL idp_session_id must survive.
	insertSession(t, "sess-ropc", "user-1", "", "at-ropc")
	insertToken(t, "tok-ropc", "user-1", "at-ropc")

	require.NoError(t, DeactivateWithCascade("idp-target"))

	// Target IdP session deactivated.
	var deactivatedAt *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = 'idp-target'`,
	).Scan(&deactivatedAt))
	assert.NotNil(t, deactivatedAt, "target idp_session must be deactivated")

	// Child sessions deactivated.
	for _, sid := range []string{"sess-1", "sess-2"} {
		var da *time.Time
		require.NoError(t, db.GetDB().QueryRow(
			`SELECT deactivated_at FROM sessions WHERE id = ?`, sid,
		).Scan(&da))
		assert.NotNil(t, da, "child session %s must be deactivated", sid)
	}

	// Child tokens revoked.
	for _, tid := range []string{"tok-1", "tok-2"} {
		var ra *time.Time
		require.NoError(t, db.GetDB().QueryRow(
			`SELECT revoked_at FROM tokens WHERE id = ?`, tid,
		).Scan(&ra))
		assert.NotNil(t, ra, "child token %s must be revoked", tid)
	}

	// Unrelated idp_session untouched.
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = 'idp-other'`,
	).Scan(&deactivatedAt))
	assert.Nil(t, deactivatedAt, "unrelated idp_session must survive")

	// Unrelated session + token untouched.
	var da *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM sessions WHERE id = 'sess-other'`,
	).Scan(&da))
	assert.Nil(t, da, "unrelated child session must survive")

	var ra *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT revoked_at FROM tokens WHERE id = 'tok-other'`,
	).Scan(&ra))
	assert.Nil(t, ra, "unrelated child token must survive")

	// ROPC session + token (idp_session_id NULL) untouched.
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM sessions WHERE id = 'sess-ropc'`,
	).Scan(&da))
	assert.Nil(t, da, "NULL-idp session must survive cascade")

	require.NoError(t, db.GetDB().QueryRow(
		`SELECT revoked_at FROM tokens WHERE id = 'tok-ropc'`,
	).Scan(&ra))
	assert.Nil(t, ra, "NULL-idp token must survive cascade")
}

func TestDeactivateWithCascade_IsIdempotent(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	require.NoError(t, CreateIdpSession(IdpSession{
		ID: "idp-idem", UserID: "user-1", UserAgent: "ua", IPAddress: "127.0.0.1",
	}))
	insertSession(t, "sess-idem", "user-1", "idp-idem", "at-idem")
	insertToken(t, "tok-idem", "user-1", "at-idem")

	require.NoError(t, DeactivateWithCascade("idp-idem"))

	// Capture the first deactivated_at so we can prove the second call doesn't overwrite it.
	var firstAt time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = 'idp-idem'`,
	).Scan(&firstAt))

	time.Sleep(5 * time.Millisecond)
	assert.NoError(t, DeactivateWithCascade("idp-idem"))

	var secondAt time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = 'idp-idem'`,
	).Scan(&secondAt))
	assert.Equal(t, firstAt, secondAt, "re-running cascade must not overwrite deactivated_at")
}

func TestDeactivateWithCascade_EmptyIDReturnsError(t *testing.T) {
	testutils.WithTestDB(t)
	assert.Error(t, DeactivateWithCascade(""))
}
