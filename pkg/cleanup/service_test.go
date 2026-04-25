package cleanup

import (
	"context"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func insertExpiredAuthCode(t *testing.T, id string, expiredAgo time.Duration) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO auth_codes (code, user_id, client_id, redirect_uri, scope, expires_at, used)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, "user-1", "client-1", "http://localhost/cb", "openid",
		time.Now().Add(-expiredAgo), false,
	)
	require.NoError(t, err)
}

func insertExpiredSession(t *testing.T, id string, expiredAgo time.Duration) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO sessions (id, user_id, access_token, expires_at)
		 VALUES (?, ?, ?, ?)`,
		id, "user-1", "token-"+id, time.Now().Add(-expiredAgo),
	)
	require.NoError(t, err)
}

func insertExpiredTrustedDevice(t *testing.T, id string, expiredAgo time.Duration) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO trusted_devices (id, user_id, device_name, expires_at)
		 VALUES (?, ?, ?, ?)`,
		id, "user-1", "TestBrowser", time.Now().Add(-expiredAgo),
	)
	require.NoError(t, err)
}

func insertDeactivatedIdpSession(t *testing.T, id string, deactivatedAgo time.Duration) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO idp_sessions (id, user_id, user_agent, ip_address, deactivated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, "user-1", "agent", "127.0.0.1", time.Now().Add(-deactivatedAgo),
	)
	require.NoError(t, err)
}

func rowExists(t *testing.T, table, idCol, id string) bool {
	t.Helper()
	var count int
	err := db.GetDB().QueryRow(
		"SELECT COUNT(*) FROM "+table+" WHERE "+idCol+" = ?", id,
	).Scan(&count)
	require.NoError(t, err)
	return count > 0
}

// --- Run: expired records older than retention are deleted ---

func TestRun_DeletesExpiredAuthCodes(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	old := xid.New().String()
	recent := xid.New().String()

	insertExpiredAuthCode(t, old, 48*time.Hour)    // expired 48h ago → should be deleted
	insertExpiredAuthCode(t, recent, 1*time.Hour)  // expired 1h ago  → within 24h retention, kept

	Run(24 * time.Hour)

	assert.False(t, rowExists(t, "auth_codes", "code", old), "old expired code should be deleted")
	assert.True(t, rowExists(t, "auth_codes", "code", recent), "recently expired code should be kept")
}

func TestRun_DeletesExpiredSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	old := xid.New().String()
	recent := xid.New().String()

	insertExpiredSession(t, old, 48*time.Hour)
	insertExpiredSession(t, recent, 1*time.Hour)

	Run(24 * time.Hour)

	assert.False(t, rowExists(t, "sessions", "id", old))
	assert.True(t, rowExists(t, "sessions", "id", recent))
}

func TestRun_DeletesExpiredTrustedDevices(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	old := xid.New().String()
	recent := xid.New().String()

	insertExpiredTrustedDevice(t, old, 48*time.Hour)
	insertExpiredTrustedDevice(t, recent, 1*time.Hour)

	Run(24 * time.Hour)

	assert.False(t, rowExists(t, "trusted_devices", "id", old))
	assert.True(t, rowExists(t, "trusted_devices", "id", recent))
}

func TestRun_DeletesDeactivatedIdpSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	old := xid.New().String()
	recent := xid.New().String()

	insertDeactivatedIdpSession(t, old, 48*time.Hour)
	insertDeactivatedIdpSession(t, recent, 1*time.Hour)

	Run(24 * time.Hour)

	assert.False(t, rowExists(t, "idp_sessions", "id", old))
	assert.True(t, rowExists(t, "idp_sessions", "id", recent))
}

func TestRun_KeepsActiveIdpSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	id := xid.New().String()

	// Active session: no deactivated_at, no expires_at
	_, err := db.GetDB().Exec(
		`INSERT INTO idp_sessions (id, user_id, user_agent, ip_address) VALUES (?, ?, ?, ?)`,
		id, "user-1", "agent", "127.0.0.1",
	)
	require.NoError(t, err)

	Run(24 * time.Hour)

	assert.True(t, rowExists(t, "idp_sessions", "id", id), "active session should not be deleted")
}

func TestRun_DeactivatesIdleIdpSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	prev := config.Values.AuthSsoSessionIdleTimeout
	config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	t.Cleanup(func() { config.Values.AuthSsoSessionIdleTimeout = prev })

	idle := xid.New().String()
	fresh := xid.New().String()

	// Idle row: last_activity 2h ago (well beyond 30m idle timeout).
	_, err := db.GetDB().Exec(
		`INSERT INTO idp_sessions (id, user_id, user_agent, ip_address, last_activity_at)
		 VALUES (?, ?, ?, ?, ?)`,
		idle, "user-1", "agent", "127.0.0.1", time.Now().Add(-2*time.Hour),
	)
	require.NoError(t, err)

	// Fresh row: default last_activity_at = CURRENT_TIMESTAMP.
	_, err = db.GetDB().Exec(
		`INSERT INTO idp_sessions (id, user_id, user_agent, ip_address)
		 VALUES (?, ?, ?, ?)`,
		fresh, "user-1", "agent", "127.0.0.1",
	)
	require.NoError(t, err)

	// Large retention so hard-delete pass does NOT remove the just-deactivated row —
	// we want to observe the intermediate deactivated state.
	Run(7 * 24 * time.Hour)

	var deactivatedAt *time.Time
	err = db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = ?`, idle,
	).Scan(&deactivatedAt)
	require.NoError(t, err)
	assert.NotNil(t, deactivatedAt, "idle session must be deactivated")

	err = db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = ?`, fresh,
	).Scan(&deactivatedAt)
	require.NoError(t, err)
	assert.Nil(t, deactivatedAt, "fresh session must remain active")
}

func TestRun_DeactivatesIdleIdpSessions_CascadesToChildSessionsAndTokens(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	prev := config.Values.AuthSsoSessionIdleTimeout
	config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	t.Cleanup(func() { config.Values.AuthSsoSessionIdleTimeout = prev })

	idleID := xid.New().String()

	// Create an IdP session that is idle (last activity 2h ago, well beyond 30m timeout).
	_, err := db.GetDB().Exec(
		`INSERT INTO idp_sessions (id, user_id, user_agent, ip_address, last_activity_at)
		 VALUES (?, ?, ?, ?, ?)`,
		idleID, "user-1", "agent", "127.0.0.1", time.Now().Add(-2*time.Hour),
	)
	require.NoError(t, err)

	// Child OAuth sessions linked to the idle IdP session.
	_, err = db.GetDB().Exec(
		`INSERT INTO sessions (id, user_id, access_token, refresh_token, expires_at, idp_session_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-child-1", "user-1", "at-child-1", "rt-child-1", time.Now().Add(time.Hour), idleID,
	)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(
		`INSERT INTO sessions (id, user_id, access_token, refresh_token, expires_at, idp_session_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-child-2", "user-1", "at-child-2", "rt-child-2", time.Now().Add(time.Hour), idleID,
	)
	require.NoError(t, err)

	// Tokens for those child sessions.
	_, err = db.GetDB().Exec(
		`INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tok-child-1", "user-1", "at-child-1", "rt-child-1", "Bearer",
		time.Now().Add(24*time.Hour), time.Now().Add(time.Hour),
		time.Now(), "openid", "authorization_code",
	)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(
		`INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tok-child-2", "user-1", "at-child-2", "rt-child-2", "Bearer",
		time.Now().Add(24*time.Hour), time.Now().Add(time.Hour),
		time.Now(), "openid", "authorization_code",
	)
	require.NoError(t, err)

	// Large retention so the hard-delete pass doesn't remove the deactivated row.
	Run(7 * 24 * time.Hour)

	// IdP session must be deactivated.
	var deactivatedAt *time.Time
	err = db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = ?`, idleID,
	).Scan(&deactivatedAt)
	require.NoError(t, err)
	require.NotNil(t, deactivatedAt, "idle IdP session must be deactivated")

	// Child sessions must also be deactivated.
	for _, sid := range []string{"sess-child-1", "sess-child-2"} {
		var da *time.Time
		require.NoError(t, db.GetDB().QueryRow(
			`SELECT deactivated_at FROM sessions WHERE id = ?`, sid,
		).Scan(&da))
		assert.NotNil(t, da, "child session %s must be deactivated after idle cascade", sid)
	}

	// Child tokens must be revoked.
	for _, tid := range []string{"tok-child-1", "tok-child-2"} {
		var ra *time.Time
		require.NoError(t, db.GetDB().QueryRow(
			`SELECT revoked_at FROM tokens WHERE id = ?`, tid,
		).Scan(&ra))
		assert.NotNil(t, ra, "child token %s must be revoked after idle cascade", tid)
	}
}

func TestRun_IdleSweepDisabledWhenIdleTimeoutZero(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	prev := config.Values.AuthSsoSessionIdleTimeout
	config.Values.AuthSsoSessionIdleTimeout = 0
	t.Cleanup(func() { config.Values.AuthSsoSessionIdleTimeout = prev })

	id := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO idp_sessions (id, user_id, user_agent, ip_address, last_activity_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, "user-1", "agent", "127.0.0.1", time.Now().Add(-24*time.Hour),
	)
	require.NoError(t, err)

	Run(7 * 24 * time.Hour)

	var deactivatedAt *time.Time
	err = db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = ?`, id,
	).Scan(&deactivatedAt)
	require.NoError(t, err)
	assert.Nil(t, deactivatedAt, "idle sweep must be a no-op when idle timeout is zero")
}

func TestRun_EmptyTablesNoError(t *testing.T) {
	testutils.WithTestDB(t)
	// Should not panic or error on empty tables
	assert.NotPanics(t, func() { Run(24 * time.Hour) })
}

func TestStart(t *testing.T) {
	testutils.WithTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	
	// Start with a very short interval
	go Start(ctx, 10*time.Millisecond, 24*time.Hour)
	
	// Let it run for a bit
	time.Sleep(50 * time.Millisecond)
	
	// Cancel and ensure it stops
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestRun_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	
	// Close DB to trigger error
	db.CloseDB()
	
	// Should not panic, just log errors
	Run(time.Hour)
}
