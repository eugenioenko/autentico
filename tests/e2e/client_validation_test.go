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
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()
}

// csrfTokenFromAuthorize fetches the authorize page for a known-good client
// and extracts the CSRF token. This is used to obtain a valid CSRF cookie+token
// pair before testing the login endpoint with invalid parameters.
func csrfTokenFromAuthorize(t *testing.T, ts *TestServer) string {
	t.Helper()
	resp, err := ts.Client.Get(authorizeURL(ts, "test-client", "http://localhost:3000/callback", "state"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "authorize page failed: %s", string(body))
	token := getCSRFToken(string(body))
	require.NotEmpty(t, token, "CSRF token not found in authorize page")
	return token
}

// postLogin sends a POST to /oauth2/login with the given form values and CSRF token.
func postLogin(t *testing.T, ts *TestServer, form url.Values, csrfToken string) *http.Response {
	t.Helper()
	form.Set("gorilla.csrf.Token", csrfToken)
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")
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

func TestLogin_UnknownClientID(t *testing.T) {
	ts := startTestServer(t)
	csrfToken := csrfTokenFromAuthorize(t, ts)

	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect_uri", "http://localhost:3000/callback")
	form.Set("state", "s1")
	form.Set("client_id", "nonexistent-client-xyz")

	resp := postLogin(t, ts, form, csrfToken)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "Unknown client_id")
}

func TestLogin_InactiveClient(t *testing.T) {
	ts := startTestServer(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, is_active)
		VALUES ('inactive-e2e-id', 'inactive-e2e-client', 'Inactive E2E Client', 'public', '["http://localhost:3000/callback"]', FALSE)
	`)
	require.NoError(t, err)

	csrfToken := csrfTokenFromAuthorize(t, ts)

	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect_uri", "http://localhost:3000/callback")
	form.Set("state", "s1")
	form.Set("client_id", "inactive-e2e-client")

	resp := postLogin(t, ts, form, csrfToken)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "Client is inactive")
}

func TestLogin_RedirectURINotAllowedForClient(t *testing.T) {
	ts := startTestServer(t)
	csrfToken := csrfTokenFromAuthorize(t, ts)

	// test-client only allows http://localhost:3000/callback, not evil.example.com
	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect_uri", "http://evil.example.com/callback")
	form.Set("state", "s1")
	form.Set("client_id", "test-client")

	resp := postLogin(t, ts, form, csrfToken)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "Redirect URI not allowed for this client")
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
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Invalid scope → redirect back with error=invalid_scope
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "error=invalid_scope")
}

func TestLogin_InvalidScope(t *testing.T) {
	ts := startTestServer(t)
	seedScopedClient(t)
	csrfToken := csrfTokenFromAuthorize(t, ts)

	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect_uri", "http://localhost:3000/callback")
	form.Set("state", "s1")
	form.Set("client_id", "scoped-e2e-client")
	form.Set("scope", "offline_access") // not in client's allowed scopes

	resp := postLogin(t, ts, form, csrfToken)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "invalid_scope")
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
