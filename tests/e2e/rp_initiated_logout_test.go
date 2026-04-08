package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRpInitiatedLogout_DeactivatesIdpSession verifies the full RP-Initiated Logout
// GET flow: login → GET /oauth2/logout?id_token_hint=<id_token> → /authorize shows login page.
func TestRpInitiatedLogout_DeactivatesIdpSession(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Step 1: Full auth code flow — sets the IdP session cookie in the test client's jar.
	code := performAuthorizationCodeFlowWithScope(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1", "openid profile email", "")

	// Step 2: Exchange code for tokens to obtain an id_token.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", testCodeVerifier)

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.IDToken, "id_token must be present (openid scope was requested)")

	// Step 3: Verify SSO is active — /authorize should auto-redirect (not show login page).
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state2"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	preResp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = preResp.Body.Close() }()
	assert.Equal(t, http.StatusFound, preResp.StatusCode, "SSO should be active before logout")

	// Step 4: GET /oauth2/logout with id_token_hint — RP-Initiated Logout.
	logoutURL := ts.BaseURL + "/oauth2/logout?" + url.Values{
		"id_token_hint": {tokens.IDToken},
	}.Encode()

	logoutResp, err := ts.Client.Get(logoutURL)
	require.NoError(t, err)
	defer func() { _ = logoutResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, logoutResp.StatusCode)

	// Step 5: Verify the IdP session cookie is cleared.
	cookieName := config.GetBootstrap().AuthIdpSessionCookieName
	var clearedCookie *http.Cookie
	for _, c := range logoutResp.Cookies() {
		if c.Name == cookieName {
			clearedCookie = c
			break
		}
	}
	require.NotNil(t, clearedCookie, "logout should clear the IdP session cookie")
	assert.True(t, clearedCookie.MaxAge < 0, "cleared cookie should have negative MaxAge")

	// Step 6: /authorize should now show the login page (SSO revoked).
	postResp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, postResp.StatusCode, "should show login page after RP-Initiated Logout")
	postBody, _ := io.ReadAll(postResp.Body)
	assert.True(t, strings.Contains(string(postBody), "<form"), "should render login form after logout")
}

// TestRpInitiatedLogout_PostLogoutRedirectWithState verifies that a registered
// post_logout_redirect_uri is honoured and the state parameter is passed through.
func TestRpInitiatedLogout_PostLogoutRedirectWithState(t *testing.T) {
	ts := startTestServer(t)

	postLogoutURI := "http://localhost:3000/logged-out"

	// Register a client with a post_logout_redirect_uri via the admin API.
	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")
	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:             "RP Logout Test Client",
		RedirectURIs:           []string{"http://localhost:3000/callback"},
		PostLogoutRedirectURIs: []string{postLogoutURI},
		GrantTypes:             []string{"authorization_code"},
		ClientType:             "public",
	})
	clientID := clientResp["client_id"].(string)

	// GET /oauth2/logout with client_id, post_logout_redirect_uri, and state.
	logoutURL := ts.BaseURL + "/oauth2/logout?" + url.Values{
		"client_id":               {clientID},
		"post_logout_redirect_uri": {postLogoutURI},
		"state":                   {"logout-state-xyz"},
	}.Encode()

	resp, err := ts.Client.Get(logoutURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, postLogoutURI+"?state=logout-state-xyz", resp.Header.Get("Location"))
}

// TestRpInitiatedLogout_UnregisteredURIShowsLogoutPage confirms that an unregistered
// post_logout_redirect_uri is silently rejected and the server renders the logout page.
func TestRpInitiatedLogout_UnregisteredURIShowsLogoutPage(t *testing.T) {
	ts := startTestServer(t)

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")
	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:             "RP Logout Reject Test Client",
		RedirectURIs:           []string{"http://localhost:3000/callback"},
		PostLogoutRedirectURIs: []string{"http://localhost:3000/logged-out"},
		GrantTypes:             []string{"authorization_code"},
		ClientType:             "public",
	})
	clientID := clientResp["client_id"].(string)

	logoutURL := ts.BaseURL + "/oauth2/logout?" + url.Values{
		"client_id":               {clientID},
		"post_logout_redirect_uri": {"http://evil.example.com/steal"},
	}.Encode()

	resp, err := ts.Client.Get(logoutURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "unregistered URI must be rejected, fallback to logout page")
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "signed out")
}
