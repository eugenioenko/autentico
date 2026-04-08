package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
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
	code := performAuthorizationCodeFlowWithScope(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state", "openid profile email", "")

	// 6. Exchange code for tokens
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

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
	assert.Equal(t, "user@test.com", userinfo["preferred_username"])
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
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

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
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

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
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {expectedState},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
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
	form.Set("redirect_uri", redirectURI)
	form.Set("state", expectedState)
	form.Set("client_id", "test-client")
	form.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	form.Set("code_challenge_method", "S256")
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
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

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
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

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
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "redirect mismatch should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestAuthorizationCodeFlow_IDTokenWithNonce(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Perform authorization code flow with openid scope and nonce
	code := performAuthorizationCodeFlowWithScope(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state", "openid profile email", "my-test-nonce-42")

	// Exchange code for tokens
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

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
	assert.NotEmpty(t, tokens.IDToken, "id_token should be present when openid scope is requested")
	assert.Equal(t, "Bearer", tokens.TokenType)
	assert.Contains(t, tokens.Scope, "openid")

	// OIDC Core §3.1.3.3: verify required claims in the ID token
	claims := decodeJWTPayload(t, tokens.IDToken)
	assert.NotEmpty(t, claims["iss"], "OIDC Core §3.1.3.3: iss MUST be present")
	assert.NotEmpty(t, claims["sub"], "OIDC Core §3.1.3.3: sub MUST be present")
	assert.NotEmpty(t, claims["aud"], "OIDC Core §3.1.3.3: aud MUST be present")
	assert.NotNil(t, claims["exp"], "OIDC Core §3.1.3.3: exp MUST be present")
	assert.NotNil(t, claims["iat"], "OIDC Core §3.1.3.3: iat MUST be present")
	// OIDC Core §3.1.3.3: nonce MUST be present if sent in the authorization request
	assert.Equal(t, "my-test-nonce-42", claims["nonce"], "OIDC Core §3.1.3.3: nonce must match the value sent in the authorization request")
	// OIDC Core §3.1.3.3: aud must contain the client_id
	assert.Equal(t, "test-client", claims["aud"])
}

// OIDC Core §3.1.2.1: without "openid" scope, no ID token is issued (plain OAuth 2.0 flow)
func TestAuthorizationCodeFlow_NoIDTokenWithoutOpenidScope(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Perform authorization code flow WITHOUT openid scope (using scopes test-client allows)
	code := performAuthorizationCodeFlowWithScope(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state", "profile email", "")

	// Exchange code for tokens
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

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
	assert.Empty(t, tokens.IDToken, "id_token should NOT be present without openid scope")
}

func TestAuthorizationCodeFlow_PKCE_S256(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Generate PKCE values
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Perform authorization code flow with PKCE
	code := performAuthorizationCodeFlowWithPKCE(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state", "openid", "", codeChallenge, "S256")

	// Exchange code for tokens with code_verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", codeVerifier)

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "PKCE token exchange failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)

	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.IDToken, "id_token should be present with openid scope")
}

func TestAuthorizationCodeFlow_PKCE_WrongVerifier(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := performAuthorizationCodeFlowWithPKCE(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state", "openid", "", codeChallenge, "S256")

	// Exchange code with WRONG code_verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "wrong-verifier-that-does-not-match")

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, tokenResp.StatusCode, "wrong verifier should fail: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestAuthorizationCodeFlow_PKCE_MissingVerifier(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := performAuthorizationCodeFlowWithPKCE(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state", "openid", "", codeChallenge, "S256")

	// Exchange code WITHOUT code_verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	// No code_verifier!

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, tokenResp.StatusCode, "missing verifier should fail: %s", string(body))
}

// RFC 7636 §4.6: end-to-end PKCE flow using plain method.
// plain is allowed when AuthPKCEEnforceSHA256 is disabled.
func TestAuthorizationCodeFlow_PKCE_Plain(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	// Disable S256 enforcement so plain is accepted at the authorize endpoint
	config.Values.AuthPKCEEnforceSHA256 = false
	t.Cleanup(func() { config.Values.AuthPKCEEnforceSHA256 = true })

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// For plain method, code_challenge == code_verifier
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := codeVerifier // plain: no transformation

	code := performAuthorizationCodeFlowWithPKCE(t, ts, "test-client", redirectURI, "user@test.com", "password123", "test-state", "openid", "", codeChallenge, "plain")

	// Exchange code with correct verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", codeVerifier)

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "PKCE plain exchange failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
}

// RFC 7636 §7.2: plain SHOULD NOT be used — rejected when AuthPKCEEnforceSHA256 is true (default)
func TestAuthorizationCodeFlow_PKCE_PlainRejected(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Ensure S256 enforcement is on (default)
	config.Values.AuthPKCEEnforceSHA256 = true

	// Use a client that does not follow redirects so we can inspect the Location header
	noRedirectClient := *ts.Client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"test-state"},
		"scope":                 {"openid"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"plain"},
	}.Encode()

	resp, err := noRedirectClient.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Should redirect back to redirect_uri with error=invalid_request
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.Contains(t, location, "error=invalid_request", "plain method must be rejected when S256 enforcement is enabled")
}

func TestAuthorizationCodeFlow_InvalidCSRF(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// First GET /authorize to get the CSRF cookie set (required by gorilla/csrf)
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state1"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// POST /oauth2/login with a forged CSRF token (but valid Referer and CSRF cookie)
	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect_uri", redirectURI)
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
	form2.Set("redirect_uri", redirectURI)
	form2.Set("state", "state1")
	form2.Set("client_id", "test-client")

	loginResp2, err := client2.PostForm(ts.BaseURL+"/oauth2/login", form2)
	require.NoError(t, err)
	defer func() { _ = loginResp2.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, loginResp2.StatusCode, "missing CSRF token should be rejected with 403")
}

// TestAuthorizationCodeFlow_StateWithSpecialChars verifies that a state value containing
// URL-special characters (=, &, +, spaces) is preserved byte-for-byte in the auth response
// per RFC 6749 §4.1.2. This exercises the url.Values encoding fix in login/handler.go.
func TestAuthorizationCodeFlow_StateWithSpecialChars(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"
	// state with characters that would corrupt an unencoded fmt.Sprintf redirect
	specialState := "tok=abc&foo=bar+baz"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {redirectURI},
		"state":                 {specialState},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	csrfToken := getCSRFToken(string(body))
	require.NotEmpty(t, csrfToken)

	form := url.Values{}
	form.Set("username", "user@test.com")
	form.Set("password", "password123")
	form.Set("redirect_uri", redirectURI)
	form.Set("state", specialState)
	form.Set("client_id", "test-client")
	form.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	form.Set("code_challenge_method", "S256")
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

	// RFC 6749 §4.1.2: state MUST be echoed unchanged, including special characters
	assert.Equal(t, specialState, redirectURL.Query().Get("state"), "state with special chars must be preserved exactly")
	assert.NotEmpty(t, redirectURL.Query().Get("code"))
}

// TestAuthorizationCodeFlow_ScopeExpansionOnRefresh_Rejected verifies that a refresh
// request asking for scope beyond the original grant is rejected per RFC 6749 §6.
func TestAuthorizationCodeFlow_ScopeExpansionOnRefresh_Rejected(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Obtain tokens with a limited scope
	code := performAuthorizationCodeFlowWithScope(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1", "openid", "")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.RefreshToken)

	// Refresh and request a broader scope — must be rejected
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tokens.RefreshToken)
	refreshForm.Set("scope", "openid profile email") // more than "openid"

	refreshResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", refreshForm)
	require.NoError(t, err)
	defer func() { _ = refreshResp.Body.Close() }()

	refreshBody, err := io.ReadAll(refreshResp.Body)
	require.NoError(t, err)
	// RFC 6749 §6: scope expansion MUST be rejected
	assert.Equal(t, http.StatusBadRequest, refreshResp.StatusCode, "scope expansion on refresh must be rejected: %s", string(refreshBody))
	var errResp map[string]interface{}
	_ = json.Unmarshal(refreshBody, &errResp)
	assert.Equal(t, "invalid_scope", errResp["error"])
}

// TestAuthorizationCodeFlow_ScopeDownscope verifies that a refresh request can
// narrow the scope of the original grant per RFC 6749 §6.
func TestAuthorizationCodeFlow_ScopeDownscope(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Obtain tokens with a broad scope via authorization code flow
	code := performAuthorizationCodeFlowWithScope(t, ts, "test-client", redirectURI, "user@test.com", "password123", "state1", "openid profile", "")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange failed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.RefreshToken)
	assert.Contains(t, tokens.Scope, "profile", "original grant should include profile scope")

	// Refresh with a narrower scope — must succeed
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tokens.RefreshToken)
	refreshForm.Set("scope", "openid") // subset of "openid profile"

	refreshResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", refreshForm)
	require.NoError(t, err)
	defer func() { _ = refreshResp.Body.Close() }()

	refreshBody, err := io.ReadAll(refreshResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, refreshResp.StatusCode, "scope downscope on refresh must succeed: %s", string(refreshBody))

	var newTokens token.TokenResponse
	err = json.Unmarshal(refreshBody, &newTokens)
	require.NoError(t, err)
	// RFC 6749 §6: returned scope MUST reflect the downscoped request
	assert.Equal(t, "openid", newTokens.Scope, "downscoped refresh must return the requested subset scope")
	assert.NotEmpty(t, newTokens.AccessToken)
}
