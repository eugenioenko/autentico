package e2e

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/require"
)

// RFC 7636 Appendix B test vectors — used across all e2e tests for PKCE.
const (
	testCodeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// createTestUser creates a user directly in the database.
func createTestUser(t *testing.T, username, password, email string) *user.UserResponse {
	t.Helper()
	resp, err := user.CreateUser(username, password, email)
	require.NoError(t, err, "failed to create test user")
	return resp
}

// createTestAdmin creates an admin user and returns the user response and an access token.
// Uses the autentico-admin client so the token has the required audience for admin API access.
func createTestAdmin(t *testing.T, ts *TestServer, username, password, email string) (*user.UserResponse, string) {
	t.Helper()

	usr := createTestUser(t, username, password, email)

	err := user.UpdateUser(usr.ID, user.UserUpdateRequest{
		Email: email,
		Role:  "admin",
	})
	require.NoError(t, err, "failed to set admin role")
	usr.Role = "admin"

	tokenResp := obtainTokensViaPasswordGrantForClient(t, ts, "autentico-admin", username, password)
	return usr, tokenResp.AccessToken
}

// obtainTokensViaPasswordGrant gets tokens using the password grant type with the default test-client.
func obtainTokensViaPasswordGrant(t *testing.T, ts *TestServer, username, password string) *token.TokenResponse {
	t.Helper()
	return obtainTokensViaPasswordGrantForClient(t, ts, "test-client", username, password)
}

// obtainTokensViaPasswordGrantForClient gets tokens using the password grant type for a specific client.
func obtainTokensViaPasswordGrantForClient(t *testing.T, ts *TestServer, clientID, username, password string) *token.TokenResponse {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", clientID)
	form.Set("username", username)
	form.Set("password", password)

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

// obtainTokensViaConfidentialClient gets tokens using the ROPC grant with the e2e-confidential client.
// Use this when the test needs to introspect or revoke the token, since those endpoints
// enforce that the token was issued to the calling client.
func obtainTokensViaConfidentialClient(t *testing.T, ts *TestServer, username, password string) *token.TokenResponse {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "e2e-confidential")
	form.Set("client_secret", "e2e-secret")
	form.Set("username", username)
	form.Set("password", password)

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

	// Step 1: GET /oauth2/authorize → 302 redirect to /oauth2/login?auth_request_id=xxx
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":        {"code"},
		"client_id":            {clientID},
		"redirect_uri":         {redirectURI},
		"state":                {state},
		"code_challenge":       {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err, "failed to GET /oauth2/authorize")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize should redirect to login")

	loginLocation := resp.Header.Get("Location")
	require.Contains(t, loginLocation, "auth_request_id=", "authorize redirect must contain auth_request_id")

	// Step 2: Follow redirect to GET /oauth2/login to get CSRF token
	loginPageResp, err := ts.Client.Get(ts.BaseURL + loginLocation)
	require.NoError(t, err, "failed to GET login page")
	defer func() { _ = loginPageResp.Body.Close() }()

	body, err := io.ReadAll(loginPageResp.Body)
	require.NoError(t, err, "failed to read login page")
	require.Equal(t, http.StatusOK, loginPageResp.StatusCode, "login page failed: %s", string(body))

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken, "CSRF token not found in login page")

	// Extract auth_request_id from the login page URL
	loginURL, _ := url.Parse(loginLocation)
	authRequestID := loginURL.Query().Get("auth_request_id")
	require.NotEmpty(t, authRequestID, "auth_request_id not found in login URL")

	// Step 3: POST /oauth2/login with auth_request_id + credentials + CSRF
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err, "failed to create login request")
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/login")

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
		"response_type":        {"code"},
		"client_id":            {clientID},
		"redirect_uri":         {redirectURI},
		"state":                {state},
		"code_challenge":       {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}
	if scope != "" {
		params.Set("scope", scope)
	}
	if nonce != "" {
		params.Set("nonce", nonce)
	}

	// Step 1: GET /oauth2/authorize → 302 to /oauth2/login?auth_request_id=xxx
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err, "failed to GET /oauth2/authorize")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize should redirect to login")

	loginLocation := resp.Header.Get("Location")
	loginURL, _ := url.Parse(loginLocation)
	authRequestID := loginURL.Query().Get("auth_request_id")
	require.NotEmpty(t, authRequestID, "auth_request_id not found")

	// Step 2: GET login page for CSRF
	loginPageResp, err := ts.Client.Get(ts.BaseURL + loginLocation)
	require.NoError(t, err)
	defer func() { _ = loginPageResp.Body.Close() }()
	body, _ := io.ReadAll(loginPageResp.Body)
	require.Equal(t, http.StatusOK, loginPageResp.StatusCode, "login page failed: %s", string(body))

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	// Step 3: POST /oauth2/login
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/login")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()
	require.Equal(t, http.StatusFound, loginResp.StatusCode, "login should redirect with 302")

	location := loginResp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code not found in redirect URL")

	return code
}

// performAuthorizationCodeFlowWithPKCE drives the full authorize -> login -> extract code chain
// with PKCE parameters (code_challenge and code_challenge_method).
func performAuthorizationCodeFlowWithPKCE(t *testing.T, ts *TestServer, clientID, redirectURI, username, password, state, scope, nonce, codeChallenge, codeChallengeMethod string) string {
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
	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
	}
	if codeChallengeMethod != "" {
		params.Set("code_challenge_method", codeChallengeMethod)
	}

	// Step 1: GET /oauth2/authorize → 302 to /oauth2/login?auth_request_id=xxx
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize should redirect to login")

	loginLocation := resp.Header.Get("Location")
	loginURL, _ := url.Parse(loginLocation)
	authRequestID := loginURL.Query().Get("auth_request_id")
	require.NotEmpty(t, authRequestID, "auth_request_id not found")

	// Step 2: GET login page for CSRF
	loginPageResp, err := ts.Client.Get(ts.BaseURL + loginLocation)
	require.NoError(t, err)
	defer func() { _ = loginPageResp.Body.Close() }()
	body, _ := io.ReadAll(loginPageResp.Body)
	require.Equal(t, http.StatusOK, loginPageResp.StatusCode, "login page failed: %s", string(body))

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	// Step 3: POST /oauth2/login
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/login")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()
	require.Equal(t, http.StatusFound, loginResp.StatusCode, "login should redirect with 302")

	location := loginResp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code not found in redirect URL")

	return code
}

// performSignupFlow drives the authorize?prompt=create → signup page → POST signup → extract code chain.
func performSignupFlow(t *testing.T, ts *TestServer, username, password, redirectURI, state string) string {
	t.Helper()

	// Step 1: GET /oauth2/authorize?prompt=create → 302 to /oauth2/signup?auth_request_id=xxx
	signupURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"prompt":                {"create"},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"client_id":             {"test-client"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(signupURL)
	require.NoError(t, err, "failed to GET /oauth2/authorize?prompt=create")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize?prompt=create should redirect to signup")

	signupLocation := resp.Header.Get("Location")
	require.Contains(t, signupLocation, "/oauth2/signup", "should redirect to signup page")
	require.Contains(t, signupLocation, "auth_request_id=", "should include auth_request_id")

	// Extract auth_request_id from the redirect URL
	signupRedirectURL, _ := url.Parse(signupLocation)
	authRequestID := signupRedirectURL.Query().Get("auth_request_id")
	require.NotEmpty(t, authRequestID, "auth_request_id not found in signup redirect")

	// Step 2: GET /oauth2/signup?auth_request_id=xxx to get CSRF token
	signupPageResp, err := ts.Client.Get(ts.BaseURL + signupLocation)
	require.NoError(t, err, "failed to GET signup page")
	defer func() { _ = signupPageResp.Body.Close() }()

	body, err := io.ReadAll(signupPageResp.Body)
	require.NoError(t, err, "failed to read signup page")
	require.Equal(t, http.StatusOK, signupPageResp.StatusCode, "signup page failed: %s", string(body))

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken, "CSRF token not found in signup page")

	// Step 3: POST /oauth2/signup with auth_request_id + credentials
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("confirm_password", password)
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	signupReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err, "failed to create signup request")
	signupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signupReq.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	signupResp, err := ts.Client.Do(signupReq)
	require.NoError(t, err, "failed to POST /oauth2/signup")
	defer func() { _ = signupResp.Body.Close() }()

	require.Equal(t, http.StatusFound, signupResp.StatusCode, "signup should redirect with 302")

	location := signupResp.Header.Get("Location")
	require.NotEmpty(t, location, "missing Location header in signup redirect")

	redirectURL, err := url.Parse(location)
	require.NoError(t, err, "failed to parse redirect URL")

	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code not found in redirect URL")

	returnedState := redirectURL.Query().Get("state")
	require.Equal(t, state, returnedState, "state parameter should be preserved")

	return code
}

// decodeJWTPayload decodes the payload (second segment) of a JWT without verifying the signature.
// Useful in e2e tests where we trust the server and just want to inspect claims.
func decodeJWTPayload(t *testing.T, jwtStr string) map[string]interface{} {
	t.Helper()
	parts := strings.SplitN(jwtStr, ".", 3)
	require.Len(t, parts, 3, "JWT must have 3 parts")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "failed to base64-decode JWT payload")
	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims), "failed to unmarshal JWT claims")
	return claims
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

// authorizeAndGetSignupPage performs GET /oauth2/authorize?prompt=create, follows the
// redirect to the signup page, and returns (authRequestID, csrfToken). This is the
// common setup step for tests that need to interact with the signup form.
func authorizeAndGetSignupPage(t *testing.T, ts *TestServer, params url.Values) (authRequestID, csrfToken string) {
	t.Helper()

	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize?prompt=create should redirect to signup")

	signupLocation := resp.Header.Get("Location")
	require.Contains(t, signupLocation, "/oauth2/signup", "should redirect to signup page")

	signupURL, _ := url.Parse(signupLocation)
	authRequestID = signupURL.Query().Get("auth_request_id")
	require.NotEmpty(t, authRequestID)

	signupPageResp, err := ts.Client.Get(ts.BaseURL + signupLocation)
	require.NoError(t, err)
	defer func() { _ = signupPageResp.Body.Close() }()

	body, _ := io.ReadAll(signupPageResp.Body)
	require.Equal(t, http.StatusOK, signupPageResp.StatusCode, "signup page failed: %s", string(body))

	csrfToken = getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	return authRequestID, csrfToken
}

// authorizeAndGetSignupPageWithClient performs GET /oauth2/authorize?prompt=create using
// the provided HTTP client (instead of ts.Client), follows the redirect to the signup page,
// and returns (authRequestID, csrfToken).
func authorizeAndGetSignupPageWithClient(t *testing.T, ts *TestServer, httpClient *http.Client, params url.Values) (authRequestID, csrfToken string) {
	t.Helper()

	resp, err := httpClient.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize?prompt=create should redirect to signup")

	signupLocation := resp.Header.Get("Location")
	require.Contains(t, signupLocation, "/oauth2/signup", "should redirect to signup page")

	signupURL, _ := url.Parse(signupLocation)
	authRequestID = signupURL.Query().Get("auth_request_id")
	require.NotEmpty(t, authRequestID)

	signupPageResp, err := httpClient.Get(ts.BaseURL + signupLocation)
	require.NoError(t, err)
	defer func() { _ = signupPageResp.Body.Close() }()

	body, _ := io.ReadAll(signupPageResp.Body)
	require.Equal(t, http.StatusOK, signupPageResp.StatusCode, "signup page failed: %s", string(body))

	csrfToken = getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	return authRequestID, csrfToken
}

// authorizeAndGetLoginPage performs GET /oauth2/authorize, follows the redirect to
// the login page, and returns (authRequestID, csrfToken). This is the common setup
// step for tests that need to interact with the login form.
func authorizeAndGetLoginPage(t *testing.T, ts *TestServer, params url.Values) (authRequestID, csrfToken string) {
	t.Helper()

	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize should redirect to login")

	loginLocation := resp.Header.Get("Location")
	loginURL, _ := url.Parse(loginLocation)
	authRequestID = loginURL.Query().Get("auth_request_id")
	require.NotEmpty(t, authRequestID)

	loginPageResp, err := ts.Client.Get(ts.BaseURL + loginLocation)
	require.NoError(t, err)
	defer func() { _ = loginPageResp.Body.Close() }()

	body, _ := io.ReadAll(loginPageResp.Body)
	require.Equal(t, http.StatusOK, loginPageResp.StatusCode, "login page failed: %s", string(body))

	csrfToken = getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	return authRequestID, csrfToken
}
