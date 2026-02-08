package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationCodeFlow_Complete(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	// 1. Create user
	usr := createTestUser(t, "user@test.com", "password123", "user@test.com")

	// 2-5. Perform authorization code flow (authorize -> login -> get code)
	code := performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state")

	// 6. Exchange code for tokens
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

	// 7. Verify tokens returned
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)

	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
	assert.Greater(t, tokens.ExpiresIn, 0)

	// 8. GET /oauth2/userinfo with access_token
	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	userinfoResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = userinfoResp.Body.Close() }()

	body, err = io.ReadAll(userinfoResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, userinfoResp.StatusCode, "userinfo failed: %s", string(body))

	// 9. Verify user info matches
	var userinfo map[string]interface{}
	err = json.Unmarshal(body, &userinfo)
	require.NoError(t, err)

	assert.Equal(t, usr.ID, userinfo["sub"])
	assert.Equal(t, "user@test.com", userinfo["email"])
	assert.Equal(t, "user@test.com", userinfo["username"])
}

func TestAuthorizationCodeFlow_WithRegisteredClient(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	// Create admin and register a confidential client
	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Test Confidential Client",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "confidential",
	})

	clientID := clientResp["client_id"].(string)
	clientSecret := clientResp["client_secret"].(string)

	// Create a regular user for the flow
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Perform authorization code flow with registered client
	code := performAuthorizationCodeFlow(t, ts, clientID, redirectURI, "user@test.com", "password123", "state123")

	// Exchange code using Basic Auth with client credentials
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	tokenResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange with basic auth failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)

	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
}

func TestAuthorizationCodeFlow_PublicClient(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	// Create admin and register a public client
	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Test Public Client",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "public",
	})

	clientID := clientResp["client_id"].(string)

	// Create a regular user
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Perform authorization code flow
	code := performAuthorizationCodeFlow(t, ts, clientID, redirectURI, "user@test.com", "password123", "state-pub")

	// Exchange code with only client_id (no secret)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "public client token exchange failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)

	assert.NotEmpty(t, tokens.AccessToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
}

func TestAuthorizationCodeFlow_StatePreserved(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"
	expectedState := "random-opaque-state-value-12345"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// GET /oauth2/authorize
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {expectedState},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	// POST /oauth2/login
	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect", redirectURI)
	form.Set("state", expectedState)
	form.Set("client_id", "test-client")
	form.Set("gorilla.csrf.Token", csrfToken)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	require.Equal(t, http.StatusFound, loginResp.StatusCode)

	location := loginResp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	// Verify state is preserved exactly
	assert.Equal(t, expectedState, redirectURL.Query().Get("state"), "state must be preserved unmodified")
	assert.NotEmpty(t, redirectURL.Query().Get("code"), "code must be present")
}

func TestAuthorizationCodeFlow_CodeReuse(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Get an authorization code
	code := performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1")

	// First exchange -- should succeed
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")

	resp1, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()

	body1, _ := io.ReadAll(resp1.Body)
	require.Equal(t, http.StatusOK, resp1.StatusCode, "first exchange should succeed: %s", string(body1))

	// Second exchange with same code -- should fail
	resp2, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()

	body2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode, "code reuse should fail")

	var errResp map[string]interface{}
	_ = json.Unmarshal(body2, &errResp)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestAuthorizationCodeFlow_CodeExpiry(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	usr := createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Create an auth code directly in the DB with past expiry
	expiredCode := "expired-test-code-123"
	err := authcode.CreateAuthCode(authcode.AuthCode{
		Code:        expiredCode,
		UserID:      usr.ID,
		ClientID:    "test-client",
		RedirectURI: redirectURI,
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // expired 1 hour ago
		Used:        false,
		CreatedAt:   time.Now().Add(-2 * time.Hour),
	})
	require.NoError(t, err)

	// Attempt to exchange expired code
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", expiredCode)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "expired code should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestAuthorizationCodeFlow_RedirectMismatch(t *testing.T) {
	ts := startTestServer(t)
	originalRedirectURI := "http://localhost:3000/callback"
	differentRedirectURI := "http://localhost:3000/other-callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Get a code with the original redirect_uri
	code := performAuthorizationCodeFlow(t, ts, "test-client", originalRedirectURI, "user@test.com", "password123", "state1")

	// Attempt token exchange with a different redirect_uri
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", differentRedirectURI) // Different!
	form.Set("client_id", "test-client")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "redirect mismatch should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestAuthorizationCodeFlow_InvalidCSRF(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// First GET /authorize to get the CSRF cookie set (required by gorilla/csrf)
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {"state1"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// POST /oauth2/login with a forged CSRF token (but valid Referer and CSRF cookie)
	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect", redirectURI)
	form.Set("state", "state1")
	form.Set("client_id", "test-client")
	form.Set("gorilla.csrf.Token", "invalid-forged-csrf-token")

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, loginResp.StatusCode, "invalid CSRF token should be rejected with 403")

	// Also test with completely missing CSRF token and no cookie
	client2 := newClientWithJar()
	form2 := url.Values{}
	form2.Set("username", "user@test.com")
	form2.Set("password", "password123")
	form2.Set("redirect", redirectURI)
	form2.Set("state", "state1")
	form2.Set("client_id", "test-client")

	loginResp2, err := client2.PostForm(ts.BaseURL+"/oauth2/login", form2)
	require.NoError(t, err)
	defer func() { _ = loginResp2.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, loginResp2.StatusCode, "missing CSRF token should be rejected with 403")
}
