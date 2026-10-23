package security

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
)

// RFC 6750 §5.2: an admin's token issued to an ordinary relying party must
// not authorize privileged cross-client operations at this resource server.
func TestRevocationRequiresAdminAudience(t *testing.T) {
	ts := startTestServer(t)
	_, admin := createTestAdmin(t, ts, "revoke-admin", "password123", "admin@example.com")
	ordinary := obtainTokensViaROPC(t, ts, "test-client", "revoke-admin", "password123")
	createTestUser(t, "revoke-target", "password123", "target@example.com")
	target := obtainTokensViaConfidentialROPC(t, ts, "revoke-target", "password123")
	request := func(caller, credential string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/revoke", strings.NewReader(url.Values{"token": {credential}}.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+caller)
		response, err := ts.Client.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		require.NoError(t, err)
		if response.StatusCode != http.StatusOK {
			require.Equal(t, http.StatusForbidden, response.StatusCode, string(body))
			require.Contains(t, response.Header.Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`)
			require.Contains(t, string(body), "insufficient_scope")
		}
		return response
	}
	for _, credential := range []string{target.AccessToken, target.RefreshToken} {
		require.Equal(t, http.StatusForbidden, request(ordinary.AccessToken, credential).StatusCode)
	}
	var revoked int
	require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM tokens WHERE revoked_at IS NOT NULL").Scan(&revoked))
	require.Zero(t, revoked, "rejected requests must not mutate tokens")
	require.Equal(t, http.StatusOK, request(admin, target.AccessToken).StatusCode)
	require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM tokens WHERE revoked_at IS NOT NULL").Scan(&revoked))
	require.Equal(t, 1, revoked)
}
