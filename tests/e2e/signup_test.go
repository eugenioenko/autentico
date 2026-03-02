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

	signupURL := ts.BaseURL + "/oauth2/signup?" + url.Values{
		"redirect_uri": {"http://localhost:3000/callback"},
		"state":        {"abc123"},
		"client_id":    {"test-client"},
	}.Encode()

	resp, err := ts.Client.Get(signupURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, `name="username"`)
	assert.Contains(t, bodyStr, `name="password"`)
	assert.Contains(t, bodyStr, `name="confirm_password"`)
	assert.Contains(t, bodyStr, `value="abc123"`)
	assert.NotEmpty(t, getCSRFToken(bodyStr), "CSRF token should be present")
}

func TestSelfSignup_Complete(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ValidationUsernameIsEmail = false
	redirectURI := "http://localhost:3000/callback"

	// Signup → get auth code
	code := performSignupFlow(t, ts, "brandnewuser", "password123", redirectURI, "test-state")

	// Exchange code for tokens
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
	assert.Equal(t, "brandnewuser", userinfo["username"])
}

func TestSelfSignup_StatePreserved(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ValidationUsernameIsEmail = false
	redirectURI := "http://localhost:3000/callback"
	expectedState := "opaque-state-value-99"

	// GET signup page
	signupURL := ts.BaseURL + "/oauth2/signup?" + url.Values{
		"redirect_uri": {redirectURI},
		"state":        {expectedState},
		"client_id":    {"test-client"},
	}.Encode()

	resp, err := ts.Client.Get(signupURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	// POST signup
	form := url.Values{}
	form.Set("username", "stateuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", expectedState)
	form.Set("client_id", "test-client")
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

func TestSelfSignup_PasswordMismatch(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ValidationUsernameIsEmail = false
	redirectURI := "http://localhost:3000/callback"

	// GET signup page for CSRF token
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/signup?redirect_uri=" + url.QueryEscape(redirectURI) + "&state=s1&client_id=test-client")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	form := url.Values{}
	form.Set("username", "someuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "different456")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "s1")
	form.Set("client_id", "test-client")
	form.Set("gorilla.csrf.Token", csrfToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	postResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()

	respBody, _ := io.ReadAll(postResp.Body)
	assert.Equal(t, http.StatusOK, postResp.StatusCode, "should re-render form on mismatch")
	assert.Contains(t, string(respBody), "Passwords do not match")
}

func TestSelfSignup_DuplicateUser(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ValidationUsernameIsEmail = false
	redirectURI := "http://localhost:3000/callback"

	// First signup succeeds
	performSignupFlow(t, ts, "dupuser", "password123", redirectURI, "s1")

	// Use a fresh client with a new cookie jar to avoid SSO auto-login
	freshClient := newClientWithJar()

	// GET signup page for a new CSRF token
	resp, err := freshClient.Get(ts.BaseURL + "/oauth2/signup?redirect_uri=" + url.QueryEscape(redirectURI) + "&state=s2&client_id=test-client")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	form := url.Values{}
	form.Set("username", "dupuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "s2")
	form.Set("client_id", "test-client")
	form.Set("gorilla.csrf.Token", csrfToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	postResp, err := freshClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()

	respBody, _ := io.ReadAll(postResp.Body)
	assert.Equal(t, http.StatusOK, postResp.StatusCode, "should re-render form on duplicate")
	assert.Contains(t, string(respBody), "Could not create account")
}

// TestSelfSignup_UsernameIsEmail verifies that when ValidationUsernameIsEmail is true
// the signup handler uses the username value as the email for storage, so multiple
// users can register without hitting the unique email constraint.
func TestSelfSignup_UsernameIsEmail(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true
	config.Values.ValidationUsernameIsEmail = true
	redirectURI := "http://localhost:3000/callback"

	// First signup — email-format username, no separate email field
	firstCode := performSignupFlow(t, ts, "alice@example.com", "password123", redirectURI, "s1")
	require.NotEmpty(t, firstCode, "first signup should produce an auth code")

	// Use a fresh client so the IdP session cookie doesn't cause auto-login
	freshClient := newClientWithJar()
	signupURL := ts.BaseURL + "/oauth2/signup?" + url.Values{
		"redirect_uri": {redirectURI},
		"state":        {"s2"},
		"client_id":    {"test-client"},
	}.Encode()
	resp, err := freshClient.Get(signupURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	// Second signup with a different email — must succeed without hitting unique constraint
	form := url.Values{}
	form.Set("username", "bob@example.com")
	form.Set("password", "password456")
	form.Set("confirm_password", "password456")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "s2")
	form.Set("client_id", "test-client")
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

	// Seed the CSRF cookie by visiting the signup page first
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/signup?redirect_uri=" + url.QueryEscape(redirectURI) + "&state=s1&client_id=test-client")
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
