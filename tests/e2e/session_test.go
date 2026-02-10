package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogout_DeactivatesSession(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Logout
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/logout", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	logoutResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = logoutResp.Body.Close() }()
	require.Equal(t, http.StatusOK, logoutResp.StatusCode)

	// Userinfo should reject the deactivated session's token
	req2, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	resp, err := ts.Client.Do(req2)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "userinfo should reject after logout")
}

func TestLogout_DeactivatesIdpSession(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Login via auth code flow — this sets the IdP session cookie
	code := performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1")

	// Exchange code for tokens (needed for logout)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange failed: %s", string(body))

	// Extract access token
	accessToken := extractJSONField(t, body, "access_token")

	// Logout — should deactivate IdP session and clear cookie
	logoutReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/logout", nil)
	require.NoError(t, err)
	logoutReq.Header.Set("Authorization", "Bearer "+accessToken)

	logoutResp, err := ts.Client.Do(logoutReq)
	require.NoError(t, err)
	defer func() { _ = logoutResp.Body.Close() }()
	require.Equal(t, http.StatusOK, logoutResp.StatusCode)

	// Verify the IdP cookie is cleared in the response
	cookieName := config.Get().AuthIdpSessionCookieName
	var clearedCookie *http.Cookie
	for _, c := range logoutResp.Cookies() {
		if c.Name == cookieName {
			clearedCookie = c
			break
		}
	}
	require.NotNil(t, clearedCookie, "logout response should clear the IdP session cookie")
	assert.Equal(t, "", clearedCookie.Value)
	assert.True(t, clearedCookie.MaxAge < 0, "cleared cookie should have negative MaxAge")

	// Visit /authorize again — should show login page (not auto-redirect)
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {"state2"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "should show login page, not auto-redirect")
}

func TestLogout_MissingToken(t *testing.T) {
	ts := startTestServer(t)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/logout", nil)
	require.NoError(t, err)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogout_InvalidToken(t *testing.T) {
	ts := startTestServer(t)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/logout", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer garbage-token-value")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAutoLogin_ValidIdpSession(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// First login — creates IdP session and sets cookie
	_ = performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1")

	// Second visit to /authorize — should auto-login (302 with new code)
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {"state2"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode, "should auto-login with valid IdP session")

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location)

	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	assert.NotEmpty(t, redirectURL.Query().Get("code"), "redirect should contain a new auth code")
	assert.Equal(t, "state2", redirectURL.Query().Get("state"), "state should be preserved")
}

func TestAutoLogin_IdleTimeoutExpired(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthSsoSessionIdleTimeout = 5 * time.Minute
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Login — creates IdP session
	_ = performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1")

	// Manipulate last_activity_at to be past the idle timeout
	_, err := db.GetDB().Exec(`UPDATE idp_sessions SET last_activity_at = ?`, time.Now().Add(-10*time.Minute))
	require.NoError(t, err)

	// Visit /authorize — should show login page (session idle timeout expired)
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {"state2"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "should show login page when idle timeout expired")

	body, _ := io.ReadAll(resp.Body)
	assert.True(t, strings.Contains(string(body), "<form"), "should render login form")
}

func TestAutoLogin_DeactivatedIdpSession(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Login — creates IdP session
	_ = performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1")

	// Deactivate all IdP sessions in the DB
	_, err := db.GetDB().Exec(`UPDATE idp_sessions SET deactivated_at = CURRENT_TIMESTAMP`)
	require.NoError(t, err)

	// Visit /authorize — should show login page (session deactivated)
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {"state2"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "should show login page when IdP session deactivated")

	body, _ := io.ReadAll(resp.Body)
	assert.True(t, strings.Contains(string(body), "<form"), "should render login form")
}

func TestAdminSessionDeactivation_BlocksFurtherRequests(t *testing.T) {
	ts := startTestServer(t)

	// Create an admin user and get their access token
	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	// List sessions via admin API — should succeed
	req, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/sessions", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "admin should be able to list sessions")

	// Parse response to get the admin's session ID
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var listResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &listResp)
	require.NoError(t, err)
	require.NotEmpty(t, listResp.Data, "should have at least one session")
	sessionID := listResp.Data[0].ID

	// Deactivate the admin's own session
	deactivateReq, err := http.NewRequest("DELETE", ts.BaseURL+"/admin/api/sessions?id="+sessionID, nil)
	require.NoError(t, err)
	deactivateReq.Header.Set("Authorization", "Bearer "+adminToken)

	deactivateResp, err := ts.Client.Do(deactivateReq)
	require.NoError(t, err)
	defer func() { _ = deactivateResp.Body.Close() }()
	require.Equal(t, http.StatusOK, deactivateResp.StatusCode, "deactivation should succeed")

	// Now try to list sessions again — should be rejected (session deactivated)
	req2, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/sessions", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+adminToken)

	resp2, err := ts.Client.Do(req2)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, "admin request should be rejected after session deactivation")
}

// extractJSONField is a helper to extract a string field from JSON bytes.
func extractJSONField(t *testing.T, data []byte, field string) string {
	t.Helper()
	var m map[string]interface{}
	err := json.Unmarshal(data, &m)
	require.NoError(t, err)
	v, ok := m[field].(string)
	require.True(t, ok, "field %q not found or not a string", field)
	return v
}
