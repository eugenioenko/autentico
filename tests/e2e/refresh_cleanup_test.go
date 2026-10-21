package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/cleanup"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/require"
)

func TestRefreshAfterCleanupAndReplay(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "cleanup@example.com", "password123", "cleanup@example.com")
	issued := obtainTokensViaPasswordGrant(t, ts, "cleanup@example.com", "password123")
	// Model a pre-fix row whose access lifetime plus retention elapsed.
	oldExpiry := time.Now().Add(-48 * time.Hour).UTC()
	_, err := db.GetDB().Exec(`UPDATE tokens SET access_token_expires_at=? WHERE access_token_hash=?`, oldExpiry, credentialDigest(issued.AccessToken))
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE sessions SET expires_at=? WHERE access_token_hash=?`, oldExpiry, credentialDigest(issued.AccessToken))
	require.NoError(t, err)
	cleanup.Run(24 * time.Hour)
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"test-client"}, "refresh_token": {issued.RefreshToken}}
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var rotated token.TokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rotated))
	require.NoError(t, resp.Body.Close())
	// Retained legacy session/revoked token must still reach replay detection.
	cleanup.Run(24 * time.Hour)
	resp, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	var revoked *time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE refresh_token_hash=?`, credentialDigest(rotated.RefreshToken)).Scan(&revoked))
	require.NotNil(t, revoked, "replay must revoke the replacement, not merely reject the old session")
	form.Set("refresh_token", rotated.RefreshToken)
	resp, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestIssuedSessionRetainsBothTokenLifetimes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		access, refresh time.Duration
	}{
		{"refresh longer", time.Hour, 24 * time.Hour}, {"access longer", 24 * time.Hour, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := startTestServer(t)
			previous := *config.Get()
			config.Values.AuthAccessTokenExpiration = tc.access
			config.Values.AuthRefreshTokenExpiration = tc.refresh
			t.Cleanup(func() { config.Values = previous })
			createTestUser(t, "expiry@example.com", "password123", "expiry@example.com")
			issued := obtainTokensViaPasswordGrant(t, ts, "expiry@example.com", "password123")
			var sessionExpiry, accessExpiry, refreshExpiry time.Time
			require.NoError(t, db.GetDB().QueryRow(`SELECT s.expires_at,t.access_token_expires_at,t.refresh_token_expires_at FROM sessions s JOIN tokens t ON t.access_token_hash=s.access_token_hash WHERE s.access_token_hash=?`, credentialDigest(issued.AccessToken)).Scan(&sessionExpiry, &accessExpiry, &refreshExpiry))
			expected := accessExpiry
			if refreshExpiry.After(expected) {
				expected = refreshExpiry
			}
			require.True(t, sessionExpiry.Equal(expected))
		})
	}
}

func TestRefreshWhileCleanupRuns(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "concurrent-cleanup@example.com", "password123", "concurrent-cleanup@example.com")
	issued := obtainTokensViaPasswordGrant(t, ts, "concurrent-cleanup@example.com", "password123")
	original := issued.RefreshToken
	oldExpiry := time.Now().Add(-48 * time.Hour).UTC()
	_, err := db.GetDB().Exec(`UPDATE tokens SET access_token_expires_at=?; UPDATE sessions SET expires_at=?`, oldExpiry, oldExpiry)
	require.NoError(t, err)
	stop, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(stop); <-done })
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				cleanup.Run(24 * time.Hour)
			}
		}
	}()
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"test-client"}}
	for range 10 {
		form.Set("refresh_token", issued.RefreshToken)
		resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&issued))
		require.NoError(t, resp.Body.Close())
	}
	form.Set("refresh_token", original)
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	var revoked *time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE refresh_token_hash=?`, credentialDigest(issued.RefreshToken)).Scan(&revoked))
	require.NotNil(t, revoked)
}
