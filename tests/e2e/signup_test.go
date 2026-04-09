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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfSignup_Disabled(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = false

	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/signup?redirect_uri=http://localhost:3000/callback&state=s1&client_id=test-client")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSelfSignup_RendersForm(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true

	params := url.Values{
		"response_type":         {"code"},
		"prompt":                {"create"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"abc123"},
		"client_id":             {"test-client"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}

	authRequestID, csrfToken := authorizeAndGetSignupPage(t, ts, params)
	assert.NotEmpty(t, authRequestID, "auth_request_id should be present")
	assert.NotEmpty(t, csrfToken, "CSRF token should be present")
}

func TestSelfSignup_Complete(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ProfileFieldEmail = "hidden"
	redirectURI := "http://localhost:3000/callback"

	// Signup → get auth code
	code := performSignupFlow(t, ts, "brandnewuser", "password123", redirectURI, "test-state")

	// Exchange code for tokens
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

	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, "Bearer", tokens.TokenType)

	// Verify userinfo is accessible with the new token
	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	userinfoResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = userinfoResp.Body.Close() }()

	body, err = io.ReadAll(userinfoResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, userinfoResp.StatusCode, "userinfo failed: %s", string(body))

	var userinfo map[string]interface{}
	err = json.Unmarshal(body, &userinfo)
	require.NoError(t, err)
	assert.NotEmpty(t, userinfo["sub"])
}

func TestSelfSignup_StatePreserved(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ProfileFieldEmail = "hidden"
	redirectURI := "http://localhost:3000/callback"
	expectedState := "opaque-state-value-99"

	params := url.Values{
		"response_type":         {"code"},
		"prompt":                {"create"},
		"redirect_uri":          {redirectURI},
		"state":                 {expectedState},
		"client_id":             {"test-client"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}

	authRequestID, csrfToken := authorizeAndGetSignupPage(t, ts, params)

	// POST signup with auth_request_id
	form := url.Values{}
	form.Set("username", "stateuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	signupReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	signupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signupReq.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	signupResp, err := ts.Client.Do(signupReq)
	require.NoError(t, err)
	defer func() { _ = signupResp.Body.Close() }()

	require.Equal(t, http.StatusFound, signupResp.StatusCode)

	redirectURL, err := url.Parse(signupResp.Header.Get("Location"))
	require.NoError(t, err)

	assert.Equal(t, expectedState, redirectURL.Query().Get("state"), "state must be preserved unmodified")
	assert.NotEmpty(t, redirectURL.Query().Get("code"))
}

// TestSelfSignup_PromptCreate verifies the full OIDC prompt=create flow:
// GET /oauth2/authorize?prompt=create renders signup form → POST /oauth2/signup → auth code → token exchange
func TestSelfSignup_PromptCreate(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ProfileFieldEmail = "hidden"
	redirectURI := "http://localhost:3000/callback"

	// Step 1: GET /oauth2/authorize?prompt=create → redirect to signup page
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"create-state"},
		"prompt":                {"create"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}

	authRequestID, csrfToken := authorizeAndGetSignupPage(t, ts, params)

	// Step 2: POST /oauth2/signup to complete registration
	form := url.Values{}
	form.Set("username", "promptcreateuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	signupReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	signupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signupReq.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	signupResp, err := ts.Client.Do(signupReq)
	require.NoError(t, err)
	defer func() { _ = signupResp.Body.Close() }()

	require.Equal(t, http.StatusFound, signupResp.StatusCode, "signup should redirect with 302")

	location := signupResp.Header.Get("Location")
	require.NotEmpty(t, location)
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "redirect should contain auth code")
	assert.Equal(t, "create-state", redirectURL.Query().Get("state"), "state must be preserved")

	// Step 3: Exchange code for tokens
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", redirectURI)
	tokenForm.Set("client_id", "test-client")
	tokenForm.Set("code_verifier", testCodeVerifier)

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", tokenForm)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	tokenBody, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange failed: %s", string(tokenBody))

	var tokens token.TokenResponse
	err = json.Unmarshal(tokenBody, &tokens)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
}

// TestSelfSignup_PromptCreate_Disabled verifies that prompt=create with signup disabled
// shows the login page with an error message
func TestSelfSignup_PromptCreate_Disabled(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = false

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"s1"},
		"prompt":                {"create"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// Authorize now redirects to /oauth2/login?auth_request_id=xxx&error=Self-registration+is+not+enabled
	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode, "should redirect to login with error")

	loginLocation := resp.Header.Get("Location")
	assert.Contains(t, loginLocation, "/oauth2/login", "should redirect to login page")
	assert.Contains(t, loginLocation, "auth_request_id=", "should include auth_request_id")

	// Follow redirect to login page and verify the error message is rendered
	loginResp, err := ts.Client.Get(ts.BaseURL + loginLocation)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	body, _ := io.ReadAll(loginResp.Body)
	assert.Equal(t, http.StatusOK, loginResp.StatusCode)
	assert.Contains(t, string(body), "Self-registration is not enabled")
}

func TestSelfSignup_PasswordMismatch(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ProfileFieldEmail = "hidden"
	redirectURI := "http://localhost:3000/callback"

	params := url.Values{
		"response_type":         {"code"},
		"prompt":                {"create"},
		"redirect_uri":          {redirectURI},
		"state":                 {"s1"},
		"client_id":             {"test-client"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}

	authRequestID, csrfToken := authorizeAndGetSignupPage(t, ts, params)

	form := url.Values{}
	form.Set("username", "someuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "different456")
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	// Signup errors now redirect to /oauth2/signup?auth_request_id=xxx&error=...
	postResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()
	require.Equal(t, http.StatusFound, postResp.StatusCode, "should redirect on signup error")

	loc := postResp.Header.Get("Location")
	require.Contains(t, loc, "auth_request_id=")
	require.Contains(t, loc, "error=")

	// Follow the redirect to verify the error is rendered
	redirectResp, err := ts.Client.Get(ts.BaseURL + loc)
	require.NoError(t, err)
	defer func() { _ = redirectResp.Body.Close() }()

	respBody, _ := io.ReadAll(redirectResp.Body)
	assert.Equal(t, http.StatusOK, redirectResp.StatusCode, "should render signup form with error")
	assert.Contains(t, string(respBody), "Passwords do not match")
}

func TestSelfSignup_DuplicateUser(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ProfileFieldEmail = "hidden"
	redirectURI := "http://localhost:3000/callback"

	// First signup succeeds
	performSignupFlow(t, ts, "dupuser", "password123", redirectURI, "s1")

	// Use a fresh client with a new cookie jar to avoid SSO auto-login
	freshClient := newClientWithJar()

	params := url.Values{
		"response_type":         {"code"},
		"prompt":                {"create"},
		"redirect_uri":          {redirectURI},
		"state":                 {"s2"},
		"client_id":             {"test-client"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}

	authRequestID, csrfToken := authorizeAndGetSignupPageWithClient(t, ts, freshClient, params)

	form := url.Values{}
	form.Set("username", "dupuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	// Signup errors now redirect to /oauth2/signup?auth_request_id=xxx&error=...
	postResp, err := freshClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()
	require.Equal(t, http.StatusFound, postResp.StatusCode, "should redirect on signup error")

	loc := postResp.Header.Get("Location")
	require.Contains(t, loc, "auth_request_id=")
	require.Contains(t, loc, "error=")

	// Follow the redirect to verify the error is rendered
	redirectResp, err := freshClient.Get(ts.BaseURL + loc)
	require.NoError(t, err)
	defer func() { _ = redirectResp.Body.Close() }()

	respBody, _ := io.ReadAll(redirectResp.Body)
	assert.Equal(t, http.StatusOK, redirectResp.StatusCode, "should render signup form with error")
	assert.Contains(t, string(respBody), "Could not create account")
}

// TestSelfSignup_UsernameIsEmail verifies that when ValidationUsernameIsEmail is true
// the signup handler uses the username value as the email for storage, so multiple
// users can register without hitting the unique email constraint.
func TestSelfSignup_UsernameIsEmail(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ProfileFieldEmail = "is_username"
	redirectURI := "http://localhost:3000/callback"

	// First signup — email-format username, no separate email field
	firstCode := performSignupFlow(t, ts, "alice@example.com", "password123", redirectURI, "s1")
	require.NotEmpty(t, firstCode, "first signup should produce an auth code")

	// Use a fresh client so the IdP session cookie doesn't cause auto-login
	freshClient := newClientWithJar()

	params := url.Values{
		"response_type":         {"code"},
		"prompt":                {"create"},
		"redirect_uri":          {redirectURI},
		"state":                 {"s2"},
		"client_id":             {"test-client"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}

	authRequestID, csrfToken := authorizeAndGetSignupPageWithClient(t, ts, freshClient, params)

	// Second signup with a different email — must succeed without hitting unique constraint
	form := url.Values{}
	form.Set("username", "bob@example.com")
	form.Set("password", "password456")
	form.Set("confirm_password", "password456")
	form.Set("auth_request_id", authRequestID)
	form.Set("gorilla.csrf.Token", csrfToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	postResp, err := freshClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()

	respBody, _ := io.ReadAll(postResp.Body)
	assert.Equal(t, http.StatusFound, postResp.StatusCode, "second signup should succeed: %s", string(respBody))
	assert.NotEmpty(t, postResp.Header.Get("Location"))
	assert.Contains(t, postResp.Header.Get("Location"), "code=")
}

func TestSelfSignup_InvalidCSRF(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	redirectURI := "http://localhost:3000/callback"

	// Seed the CSRF cookie by visiting the authorize page with prompt=create
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"}, "prompt": {"create"},
		"redirect_uri": {redirectURI}, "state": {"s1"}, "client_id": {"test-client"},
		"code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
	}.Encode())
	require.NoError(t, err)
	_ = resp.Body.Close()

	form := url.Values{}
	form.Set("username", "csrfuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "s1")
	form.Set("gorilla.csrf.Token", "forged-invalid-csrf-token")

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	postResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, postResp.StatusCode, "forged CSRF token should be rejected")
}
