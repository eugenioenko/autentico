package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/account"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIdpSessionCascade_FullFlow exercises the end-to-end chain introduced by
// this feature:
//   authorize+login creates an idp_session and sets the cookie; the auth_code
//   it issues carries idp_session_id, which /oauth2/token copies onto the
//   sessions row. Listing /account/api/sessions returns that idp_session with
//   active_apps_count=1 and is_current=true. Deleting it cascade-deactivates
//   the OAuth session and revokes its access token — the next /account/api
//   request with that token must be rejected.
func TestIdpSessionCascade_FullFlow(t *testing.T) {
	ts := startTestServer(t)

	// SSO must be on so login creates an IdP session.
	prev := config.Values.AuthSsoSessionIdleTimeout
	config.Values.AuthSsoSessionIdleTimeout = time.Hour
	t.Cleanup(func() { config.Values.AuthSsoSessionIdleTimeout = prev })

	const (
		username    = "cascade-user@test.com"
		password    = "password123"
		redirectURI = "http://localhost:3000/callback"
	)
	createTestUser(t, username, password, username)

	// Drive authorize → login; ts.Client has a cookie jar that will capture the
	// IdP session cookie for subsequent requests.
	code := performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, username, password, "state-cascade")

	// Exchange for tokens.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", testCodeVerifier)

	tokResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokResp.Body.Close() }()
	tokBody, _ := io.ReadAll(tokResp.Body)
	require.Equal(t, http.StatusOK, tokResp.StatusCode, "token exchange failed: %s", string(tokBody))

	var tokens token.TokenResponse
	require.NoError(t, json.Unmarshal(tokBody, &tokens))
	accessToken := tokens.AccessToken
	require.NotEmpty(t, accessToken)

	// The IdP session cookie was set with Path=/oauth2, so we must query the
	// jar for that path (the jar filters cookies by path scope).
	cookies := ts.Client.Jar.Cookies(mustParseURL(t, ts.BaseURL+config.GetBootstrap().AppOAuthPath+"/authorize"))
	var idpCookieValue string
	for _, c := range cookies {
		if c.Name == config.GetBootstrap().AuthIdpSessionCookieName {
			idpCookieValue = c.Value
		}
	}
	require.NotEmpty(t, idpCookieValue, "IdP session cookie must be set after login")

	// Verify the idp_session_id was plumbed all the way through to the sessions row.
	var linkedIdp *string
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT idp_session_id FROM sessions WHERE access_token = ?`, accessToken,
	).Scan(&linkedIdp))
	require.NotNil(t, linkedIdp, "sessions.idp_session_id must be populated after code-exchange")
	assert.Equal(t, idpCookieValue, *linkedIdp, "sessions.idp_session_id must match the IdP cookie")

	// GET /account/api/sessions — expect 1 row, current, active_apps_count=1.
	listReq, err := http.NewRequest("GET", ts.BaseURL+"/account/api/sessions", nil)
	require.NoError(t, err)
	listReq.Header.Set("Authorization", "Bearer "+accessToken)
	listResp, err := ts.Client.Do(listReq)
	require.NoError(t, err)
	defer func() { _ = listResp.Body.Close() }()
	require.Equal(t, http.StatusOK, listResp.StatusCode)

	var listBody model.ApiResponse[model.ListResponse[account.SessionResponse]]
	listBodyBytes, _ := io.ReadAll(listResp.Body)
	require.NoError(t, json.Unmarshal(listBodyBytes, &listBody))
	require.Len(t, listBody.Data.Items, 1)
	assert.Equal(t, idpCookieValue, listBody.Data.Items[0].ID)
	assert.True(t, listBody.Data.Items[0].IsCurrent, "the only IdP session must be marked current")
	assert.Equal(t, 1, listBody.Data.Items[0].ActiveAppsCount)

	// DELETE the IdP session — cascade should deactivate child OAuth session + tokens.
	delReq, err := http.NewRequest("DELETE", ts.BaseURL+"/account/api/sessions/"+idpCookieValue, nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+accessToken)
	delResp, err := ts.Client.Do(delReq)
	require.NoError(t, err)
	defer func() { _ = delResp.Body.Close() }()
	require.Equal(t, http.StatusOK, delResp.StatusCode)

	// Child session deactivated.
	var sessionDeactivated *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM sessions WHERE access_token = ?`, accessToken,
	).Scan(&sessionDeactivated))
	assert.NotNil(t, sessionDeactivated, "child OAuth session must be cascade-deactivated")

	// Child token revoked.
	var tokenRevoked *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT revoked_at FROM tokens WHERE access_token = ?`, accessToken,
	).Scan(&tokenRevoked))
	assert.NotNil(t, tokenRevoked, "child access token must be cascade-revoked")

	// Verify the cascade via /oauth2/introspect — active=false confirms downstream
	// bearer checks will reject the token.
	introspectReq, err := http.NewRequest(
		"POST",
		ts.BaseURL+"/oauth2/introspect",
		strings.NewReader(url.Values{"token": {accessToken}}.Encode()),
	)
	require.NoError(t, err)
	introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectReq.SetBasicAuth("e2e-confidential", "e2e-secret")
	introspectResp, err := ts.Client.Do(introspectReq)
	require.NoError(t, err)
	defer func() { _ = introspectResp.Body.Close() }()

	introspectBody, _ := io.ReadAll(introspectResp.Body)
	var introspectResult map[string]interface{}
	require.NoError(t, json.Unmarshal(introspectBody, &introspectResult))
	active, _ := introspectResult["active"].(bool)
	assert.False(t, active, "introspect must report revoked token as inactive: %s", string(introspectBody))
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}
