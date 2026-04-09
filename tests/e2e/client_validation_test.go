package e2e

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authorizeURL builds a /oauth2/authorize URL with the given parameters.
func authorizeURL(ts *TestServer, clientID, redirectURI, state string) string {
	return ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
}

// csrfTokenFromAuthorize fetches the authorize page for a known-good client,
// follows the redirect to the login page, and extracts the CSRF token.
// This is used to obtain a valid CSRF cookie+token pair before testing
// the login endpoint with invalid parameters.
func csrfTokenFromAuthorize(t *testing.T, ts *TestServer) string {
	t.Helper()
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"state"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}
	_, csrfToken := authorizeAndGetLoginPage(t, ts, params)
	return csrfToken
}

// postLogin sends a POST to /oauth2/login with the given form values and CSRF token.
func postLogin(t *testing.T, ts *TestServer, form url.Values, csrfToken string) *http.Response {
	t.Helper()
	form.Set("gorilla.csrf.Token", csrfToken)
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/login")
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	return resp
}

// --- /oauth2/authorize tests ---

func TestAuthorize_UnknownClientID(t *testing.T) {
	ts := startTestServer(t)

	resp, err := ts.Client.Get(authorizeURL(ts, "nonexistent-client-xyz", "http://localhost:3000/callback", "s1"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "Unknown client_id")
}

func TestAuthorize_RedirectURINotRegistered(t *testing.T) {
	ts := startTestServer(t)

	// test-client only allows http://localhost:3000/callback
	resp, err := ts.Client.Get(authorizeURL(ts, "test-client", "http://evil.example.com/callback", "s1"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "Redirect URI not allowed")
}

// --- /oauth2/login tests ---

// TestLogin_MissingAuthRequestID verifies that POST /oauth2/login without an
// auth_request_id returns an error (server-side authorize request storage).
func TestLogin_MissingAuthRequestID(t *testing.T) {
	ts := startTestServer(t)
	csrfToken := csrfTokenFromAuthorize(t, ts)

	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")

	resp := postLogin(t, ts, form, csrfToken)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "Missing authorization request")
}


// seedScopedClient inserts a client that only allows "openid profile" scopes.
func seedScopedClient(t *testing.T) {
	t.Helper()
	_, err := db.GetDB().Exec(`
		INSERT OR IGNORE INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, response_types, grant_types, is_active)
		VALUES ('scoped-e2e-id', 'scoped-e2e-client', 'Scoped E2E Client', 'public',
		        '["http://localhost:3000/callback"]', 'openid profile', '["code"]', '["authorization_code","password","refresh_token"]', TRUE)
	`)
	require.NoError(t, err)
}

func TestAuthorize_InvalidScope(t *testing.T) {
	ts := startTestServer(t)
	seedScopedClient(t)

	// scoped-e2e-client only allows "openid profile"; requesting "offline_access" must fail
	authURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"scoped-e2e-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"s1"},
		"scope":                 {"offline_access"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Invalid scope → redirect back with error=invalid_scope
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "error=invalid_scope")
}

// TestLogin_InvalidScope_NowHandledByAuthorize verifies that scope validation
// is handled by the authorize endpoint, which stores valid params server-side.
// The login endpoint trusts the stored params and no longer validates scope.
func TestLogin_InvalidScope_NowHandledByAuthorize(t *testing.T) {
	ts := startTestServer(t)
	seedScopedClient(t)

	// Attempting invalid scope at authorize endpoint → redirect back with error
	authURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"scoped-e2e-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"s1"},
		"scope":                 {"offline_access"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "error=invalid_scope")
}

func TestToken_PasswordGrant_InvalidScope(t *testing.T) {
	ts := startTestServer(t)
	seedScopedClient(t)
	createTestUser(t, "scopeuser", "password123", "scope@test.com")

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "scoped-e2e-client")
	form.Set("username", "scopeuser")
	form.Set("password", "password123")
	form.Set("scope", "offline_access") // not allowed for this client

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "invalid_scope")
}
