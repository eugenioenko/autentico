package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/require"
)

// createTestUser creates a user directly in the database.
func createTestUser(t *testing.T, username, password, email string) *user.UserResponse {
	t.Helper()
	resp, err := user.CreateUser(username, password, email)
	require.NoError(t, err, "failed to create test user")
	return resp
}

// createTestAdmin creates an admin user and returns the user response and an access token.
func createTestAdmin(t *testing.T, ts *TestServer, username, password, email string) (*user.UserResponse, string) {
	t.Helper()

	usr := createTestUser(t, username, password, email)

	err := user.UpdateUser(usr.ID, email, "admin")
	require.NoError(t, err, "failed to set admin role")
	usr.Role = "admin"

	tokenResp := obtainTokensViaPasswordGrant(t, ts, username, password)
	return usr, tokenResp.AccessToken
}

// obtainTokensViaPasswordGrant gets tokens using the password grant type.
func obtainTokensViaPasswordGrant(t *testing.T, ts *TestServer, username, password string) *token.TokenResponse {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("client_id", config.Get().AuthDefaultClientID)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err, "failed to post password grant")
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read token response body")
	require.Equal(t, http.StatusOK, resp.StatusCode, "password grant failed: %s", string(body))

	var tokenResp token.TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err, "failed to unmarshal token response")

	return &tokenResp
}

// performAuthorizationCodeFlow drives the full authorize -> login -> extract code chain.
func performAuthorizationCodeFlow(t *testing.T, ts *TestServer, clientID, redirectURI, username, password, state string) string {
	t.Helper()

	// Step 1: GET /oauth2/authorize to get login page with CSRF token
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {state},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err, "failed to GET /oauth2/authorize")
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read authorize response")
	require.Equal(t, http.StatusOK, resp.StatusCode, "authorize page failed: %s", string(body))

	// Step 2: Extract CSRF token from the HTML
	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken, "CSRF token not found in authorize page")

	// Step 3: POST /oauth2/login with credentials and CSRF token
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("redirect", redirectURI)
	form.Set("state", state)
	form.Set("client_id", clientID)
	form.Set("gorilla.csrf.Token", csrfToken)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err, "failed to create login request")
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err, "failed to POST /oauth2/login")
	defer func() { _ = loginResp.Body.Close() }()

	require.Equal(t, http.StatusFound, loginResp.StatusCode, "login should redirect with 302")

	// Step 4: Extract authorization code from redirect Location header
	location := loginResp.Header.Get("Location")
	require.NotEmpty(t, location, "missing Location header in login redirect")

	redirectURL, err := url.Parse(location)
	require.NoError(t, err, "failed to parse redirect URL")

	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code not found in redirect URL")

	returnedState := redirectURL.Query().Get("state")
	require.Equal(t, state, returnedState, "state parameter should be preserved")

	return code
}

// performAuthorizationCodeFlowWithScope drives the full authorize -> login -> extract code chain
// with explicit scope and nonce parameters.
func performAuthorizationCodeFlowWithScope(t *testing.T, ts *TestServer, clientID, redirectURI, username, password, state, scope, nonce string) string {
	t.Helper()

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {state},
	}
	if scope != "" {
		params.Set("scope", scope)
	}
	if nonce != "" {
		params.Set("nonce", nonce)
	}

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + params.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err, "failed to GET /oauth2/authorize")
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read authorize response")
	require.Equal(t, http.StatusOK, resp.StatusCode, "authorize page failed: %s", string(body))

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken, "CSRF token not found in authorize page")

	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("redirect", redirectURI)
	form.Set("state", state)
	form.Set("client_id", clientID)
	form.Set("scope", scope)
	form.Set("nonce", nonce)
	form.Set("gorilla.csrf.Token", csrfToken)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err, "failed to create login request")
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err, "failed to POST /oauth2/login")
	defer func() { _ = loginResp.Body.Close() }()

	require.Equal(t, http.StatusFound, loginResp.StatusCode, "login should redirect with 302")

	location := loginResp.Header.Get("Location")
	require.NotEmpty(t, location, "missing Location header in login redirect")

	redirectURL, err := url.Parse(location)
	require.NoError(t, err, "failed to parse redirect URL")

	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code not found in redirect URL")

	return code
}

// createTestClient creates an OAuth2 client via the admin API endpoint.
func createTestClient(t *testing.T, ts *TestServer, adminToken string, reqBody interface{}) map[string]interface{} {
	t.Helper()

	bodyBytes, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/register", strings.NewReader(string(bodyBytes)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "client registration failed: %s", string(body))

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	return result
}
