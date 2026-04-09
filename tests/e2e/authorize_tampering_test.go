package e2e

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogin_TamperedScope verifies that modifying the scope hidden field after
// the authorize page is rendered results in an HMAC signature mismatch rejection.
// This is the scope escalation attack described in #186.
func TestLogin_TamperedScope(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "tamper-scope-user", "password123", "tamper@test.com")

	// GET /oauth2/authorize with narrow scope
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state1"},
		"scope":                 {"openid"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode())
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	htmlBody := string(body)
	csrfToken := getCSRFToken(htmlBody)
	authorizeSig := getAuthorizeSig(htmlBody)
	require.NotEmpty(t, csrfToken)
	require.NotEmpty(t, authorizeSig)

	// POST /oauth2/login with escalated scope (offline_access added)
	form := url.Values{}
	form.Set("username", "tamper-scope-user")
	form.Set("password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "state1")
	form.Set("client_id", "test-client")
	form.Set("scope", "openid profile email offline_access") // tampered
	form.Set("code_challenge", testCodeChallenge)
	form.Set("code_challenge_method", "S256")
	form.Set("gorilla.csrf.Token", csrfToken)
	form.Set("authorize_sig", authorizeSig) // sig was computed for "openid" only

	loginReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	respBody, _ := io.ReadAll(loginResp.Body)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode, "tampered scope should be rejected")
	assert.Contains(t, string(respBody), "tampered")
}

// TestLogin_TamperedPKCE verifies that stripping PKCE parameters after the
// authorize page is rendered results in rejection. This is the PKCE downgrade
// attack described in #186.
func TestLogin_TamperedPKCE(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "tamper-pkce-user", "password123", "tamper-pkce@test.com")

	// GET /oauth2/authorize with PKCE
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state1"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode())
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	htmlBody := string(body)
	csrfToken := getCSRFToken(htmlBody)
	authorizeSig := getAuthorizeSig(htmlBody)

	// POST /oauth2/login with PKCE stripped
	form := url.Values{}
	form.Set("username", "tamper-pkce-user")
	form.Set("password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "state1")
	form.Set("client_id", "test-client")
	form.Set("code_challenge", "")        // stripped
	form.Set("code_challenge_method", "") // stripped
	form.Set("gorilla.csrf.Token", csrfToken)
	form.Set("authorize_sig", authorizeSig) // sig was computed with PKCE

	loginReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	respBody, _ := io.ReadAll(loginResp.Body)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode, "stripped PKCE should be rejected")
	assert.Contains(t, string(respBody), "tampered")
}

// TestLogin_TamperedNonce verifies that injecting a nonce when the original
// authorize request had none is rejected. This is the nonce injection attack
// described in #184.
func TestLogin_TamperedNonce(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "tamper-nonce-user", "password123", "tamper-nonce@test.com")

	// GET /oauth2/authorize with no nonce
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state1"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode())
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	htmlBody := string(body)
	csrfToken := getCSRFToken(htmlBody)
	authorizeSig := getAuthorizeSig(htmlBody)

	// POST /oauth2/login with injected nonce
	form := url.Values{}
	form.Set("username", "tamper-nonce-user")
	form.Set("password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "state1")
	form.Set("client_id", "test-client")
	form.Set("nonce", "attacker-injected-nonce") // injected
	form.Set("code_challenge", testCodeChallenge)
	form.Set("code_challenge_method", "S256")
	form.Set("gorilla.csrf.Token", csrfToken)
	form.Set("authorize_sig", authorizeSig) // sig was computed with empty nonce

	loginReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	respBody, _ := io.ReadAll(loginResp.Body)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode, "injected nonce should be rejected")
	assert.Contains(t, string(respBody), "tampered")
}

// TestLogin_MissingSig verifies that a login request without any authorize_sig
// is rejected (e.g., a crafted request that bypasses the authorize page entirely).
func TestLogin_MissingSig(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "nosig-user", "password123", "nosig@test.com")

	// Get a CSRF token from the authorize page
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state1"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode())
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	csrfToken := getCSRFToken(string(body))

	// POST /oauth2/login without authorize_sig
	form := url.Values{}
	form.Set("username", "nosig-user")
	form.Set("password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "state1")
	form.Set("client_id", "test-client")
	form.Set("code_challenge", testCodeChallenge)
	form.Set("code_challenge_method", "S256")
	form.Set("gorilla.csrf.Token", csrfToken)
	// deliberately omit authorize_sig

	loginReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	respBody, _ := io.ReadAll(loginResp.Body)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode, "missing sig should be rejected")
	assert.Contains(t, string(respBody), "tampered")
}

// TestSignup_TamperedScope verifies that modifying the scope hidden field in
// the signup form is rejected by the HMAC check.
func TestSignup_TamperedScope(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAllowSelfSignup = true

	redirectURI := "http://localhost:3000/callback"

	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"prompt":                {"create"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state1"},
		"scope":                 {"openid"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode())
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	htmlBody := string(body)
	csrfToken := getCSRFToken(htmlBody)
	authorizeSig := getAuthorizeSig(htmlBody)

	form := url.Values{}
	form.Set("username", "tamper-signup-user")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "state1")
	form.Set("client_id", "test-client")
	form.Set("scope", "openid profile email offline_access") // tampered
	form.Set("code_challenge", testCodeChallenge)
	form.Set("code_challenge_method", "S256")
	form.Set("gorilla.csrf.Token", csrfToken)
	form.Set("authorize_sig", authorizeSig) // computed for "openid"

	signupReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/signup", strings.NewReader(form.Encode()))
	signupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signupReq.Header.Set("Referer", ts.BaseURL+"/oauth2/signup")

	signupResp, err := ts.Client.Do(signupReq)
	require.NoError(t, err)
	defer func() { _ = signupResp.Body.Close() }()

	respBody, _ := io.ReadAll(signupResp.Body)
	assert.Equal(t, http.StatusBadRequest, signupResp.StatusCode, "tampered scope in signup should be rejected")
	assert.Contains(t, string(respBody), "tampered")
}
