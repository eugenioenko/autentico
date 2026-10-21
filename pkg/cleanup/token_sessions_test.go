package cleanup

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func insertTokenSession(t *testing.T, id string, accessExpiry, refreshExpiry, sessionExpiry time.Time, revoked bool) {
	t.Helper()
	var revokedAt any
	if revoked {
		revokedAt = accessExpiry.Add(-time.Hour)
	}
	_, err := db.GetDB().Exec(`INSERT INTO tokens (id,user_id,access_token_hash,refresh_token_hash,access_token_type,access_token_expires_at,refresh_token_expires_at,scope,grant_type,revoked_at) VALUES (?,'user-1',?,?,'Bearer',?,?,'openid','refresh_token',?)`, id, "access-"+id, "refresh-"+id, accessExpiry, refreshExpiry, revokedAt)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`INSERT INTO sessions(id,user_id,access_token_hash,refresh_token_hash,expires_at,deactivated_at) VALUES (?,'user-1',?,?,?,?)`, id, "access-"+id, "refresh-"+id, sessionExpiry, revokedAt)
	require.NoError(t, err)
}

func TestCleanTokenSessionsLifetimes(t *testing.T) {
	cutoff := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                     string
		access, refresh, session time.Duration
		revoked, keep            bool
	}{
		{"live refresh repairs legacy session", -2 * time.Hour, 24 * time.Hour, -2 * time.Hour, false, true},
		{"revoked replay evidence retained", -2 * time.Hour, 24 * time.Hour, -2 * time.Hour, true, true},
		{"access outlives refresh", 24 * time.Hour, -2 * time.Hour, -2 * time.Hour, false, true},
		{"retention boundary kept", 0, -time.Hour, -time.Hour, false, true},
		{"fully expired removed", -2 * time.Hour, -time.Hour, -2 * time.Hour, false, false},
		{"fully expired revoked removed", -2 * time.Hour, -time.Hour, -2 * time.Hour, true, false},
		{"later existing session preserved", -2 * time.Hour, -time.Hour, 24 * time.Hour, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestUser(t, "user-1")
			access, refresh, stored := cutoff.Add(tc.access), cutoff.Add(tc.refresh), cutoff.Add(tc.session)
			insertTokenSession(t, "pair", access, refresh, stored, tc.revoked)
			require.NoError(t, cleanTokenSessions(cutoff))
			require.Equal(t, tc.keep, rowExists(t, "sessions", "id", "pair"))
			require.Equal(t, !access.Before(cutoff) || !refresh.Before(cutoff), rowExists(t, "tokens", "id", "pair"))
			if tc.keep {
				var expiry time.Time
				var deactivated *time.Time
				require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at,deactivated_at FROM sessions WHERE id='pair'`).Scan(&expiry, &deactivated))
				expected := stored
				if access.After(expected) {
					expected = access
				}
				if refresh.After(expected) {
					expected = refresh
				}
				require.True(t, expiry.Equal(expected))
				require.Equal(t, tc.revoked, deactivated != nil)
			}
			require.NoError(t, cleanTokenSessions(cutoff), "idempotent")
		})
	}
}

func TestCleanTokenSessionsOffsetsAndOrphans(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	cutoff := time.Date(2026, 10, 20, 12, 0, 0, 0, time.FixedZone("EAT", 14*3600))
	insertTokenSession(t, "live", cutoff.Add(-time.Hour).UTC(), cutoff.Add(time.Hour).UTC(), cutoff.Add(-time.Hour).UTC(), false)
	insertTokenSession(t, "expired", cutoff.Add(-time.Hour).In(time.FixedZone("WST", -12*3600)), cutoff.Add(-time.Hour), cutoff.Add(-time.Hour), false)
	_, err := db.GetDB().Exec(`INSERT INTO sessions(id,user_id,expires_at) VALUES ('old-orphan','user-1',?),('fresh-orphan','user-1',?),('null-orphan','user-1',NULL)`, cutoff.Add(-time.Hour), cutoff.Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, cleanTokenSessions(cutoff))
	require.True(t, rowExists(t, "sessions", "id", "live"))
	require.True(t, rowExists(t, "tokens", "id", "live"))
	require.False(t, rowExists(t, "sessions", "id", "expired"))
	require.False(t, rowExists(t, "tokens", "id", "expired"))
	require.False(t, rowExists(t, "sessions", "id", "old-orphan"))
	require.True(t, rowExists(t, "sessions", "id", "fresh-orphan"))
	require.True(t, rowExists(t, "sessions", "id", "null-orphan"))
}

func TestCleanTokenSessionsBindingAndRollback(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	cutoff := time.Now().UTC()
	insertTokenSession(t, "live", cutoff.Add(-time.Hour), cutoff.Add(time.Hour), cutoff.Add(-time.Hour), true)
	insertTokenSession(t, "expired", cutoff.Add(-time.Hour), cutoff.Add(-time.Hour), cutoff.Add(-time.Hour), false)
	_, err := db.GetDB().Exec(`CREATE TRIGGER fail_token_cleanup BEFORE DELETE ON tokens BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END`)
	require.NoError(t, err)
	require.ErrorContains(t, cleanTokenSessions(cutoff), "injected cleanup failure")
	require.True(t, rowExists(t, "sessions", "id", "expired"))
	require.True(t, rowExists(t, "tokens", "id", "expired"))
	var expiry time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM sessions WHERE id='live'`).Scan(&expiry))
	require.True(t, expiry.Equal(cutoff.Add(-time.Hour)), "repair rolled back too")
	_, err = db.GetDB().Exec(`DROP TRIGGER fail_token_cleanup`)
	require.NoError(t, err)
	// A different credential pair must not extend this session.
	_, err = db.GetDB().Exec(`UPDATE sessions SET refresh_token_hash='different' WHERE id='live'`)
	require.NoError(t, err)
	require.NoError(t, cleanTokenSessions(cutoff))
	require.False(t, rowExists(t, "sessions", "id", "live"))
	require.True(t, rowExists(t, "tokens", "id", "live"))
	require.False(t, rowExists(t, "sessions", "id", "expired"))
	require.False(t, rowExists(t, "tokens", "id", "expired"))
}

func TestCleanTokenSessionsFailedCommitRestoresWriter(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	cutoff := time.Now().UTC()
	insertTokenSession(t, "live", cutoff.Add(-time.Hour), cutoff.Add(time.Hour), cutoff.Add(-time.Hour), false)
	insertTokenSession(t, "expired", cutoff.Add(-time.Hour), cutoff.Add(-time.Hour), cutoff.Add(-time.Hour), false)
	_, err := db.GetDB().Exec(`CREATE TABLE cleanup_parent(id INTEGER PRIMARY KEY);
 CREATE TABLE cleanup_deferred(id INTEGER REFERENCES cleanup_parent(id) DEFERRABLE INITIALLY DEFERRED);
 CREATE TRIGGER fail_cleanup AFTER DELETE ON tokens BEGIN INSERT INTO cleanup_deferred VALUES(1); END`)
	require.NoError(t, err)
	require.ErrorContains(t, cleanTokenSessions(cutoff), "FOREIGN KEY")
	require.True(t, rowExists(t, "tokens", "id", "expired"))
	require.True(t, rowExists(t, "sessions", "id", "expired"))
	var expiry time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM sessions WHERE id='live'`).Scan(&expiry))
	require.True(t, expiry.Equal(cutoff.Add(-time.Hour)))
	_, err = db.GetDB().Exec(`DROP TRIGGER fail_cleanup`)
	require.NoError(t, err)
	require.NoError(t, cleanTokenSessions(cutoff), "writer remains usable after commit failure")
	require.False(t, rowExists(t, "tokens", "id", "expired"))
	require.False(t, rowExists(t, "sessions", "id", "expired"))
}

func TestCleanTokenSessionsClientCredentials(t *testing.T) {
	testutils.WithTestDB(t)
	cutoff := time.Now().UTC()
	for _, id := range []string{"live", "expired"} {
		expiry := cutoff.Add(time.Hour)
		if id == "expired" {
			expiry = cutoff.Add(-time.Hour)
		}
		_, err := db.GetDB().Exec(`INSERT INTO tokens(id,user_id,access_token_hash,refresh_token_hash,access_token_type,access_token_expires_at,refresh_token_expires_at,scope,grant_type) VALUES (?,NULL,?,'','Bearer',?,?,'openid','client_credentials')`, id, id, expiry, expiry)
		require.NoError(t, err)
	}
	require.NoError(t, cleanTokenSessions(cutoff))
	require.True(t, rowExists(t, "tokens", "id", "live"))
	require.False(t, rowExists(t, "tokens", "id", "expired"))
}
