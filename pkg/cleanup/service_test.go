package cleanup

import (
	"testing"
	"time"

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

func TestRun_EmptyTablesNoError(t *testing.T) {
	testutils.WithTestDB(t)
	// Should not panic or error on empty tables
	assert.NotPanics(t, func() { Run(24 * time.Hour) })
}
