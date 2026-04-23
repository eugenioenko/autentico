package security

import (
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

const (
	testCodeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func createTestUser(t *testing.T, username, password, email string) *user.UserResponse {
	t.Helper()
	resp, err := user.CreateUser(username, password, email)
	require.NoError(t, err, "failed to create test user")
	return resp
}

func createTestAdmin(t *testing.T, ts *TestServer, username, password, email string) (*user.UserResponse, string) {
	t.Helper()
	usr := createTestUser(t, username, password, email)
	err := user.UpdateUser(usr.ID, user.UserUpdateRequest{Email: email, Role: "admin"})
	require.NoError(t, err, "failed to set admin role")
	usr.Role = "admin"
	tokenResp := obtainTokensViaROPC(t, ts, "autentico-admin", username, password)
	return usr, tokenResp.AccessToken
}

func obtainTokensViaROPC(t *testing.T, ts *TestServer, clientID, username, password string) *token.TokenResponse {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", clientID)
	form.Set("username", username)
	form.Set("password", password)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "ROPC grant failed: %s", string(body))

	var tokenResp token.TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)
	return &tokenResp
}

func obtainTokensViaConfidentialROPC(t *testing.T, ts *TestServer, username, password string) *token.TokenResponse {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "sec-confidential")
	form.Set("client_secret", "sec-secret")
	form.Set("username", username)
	form.Set("password", password)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "confidential ROPC grant failed: %s", string(body))

	var tokenResp token.TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)
	return &tokenResp
}

// performAuthCodeFlow drives authorize → login → extract code.
func performAuthCodeFlow(t *testing.T, ts *TestServer, clientID, redirectURI, username, password, state string) string {
	t.Helper()
	return performAuthCodeFlowWithPKCE(t, ts, clientID, redirectURI, username, password, state,
		"openid profile email", "", testCodeChallenge, "S256")
}

// performAuthCodeFlowWithPKCE drives the full authorize → login → extract code chain
// with explicit PKCE parameters.
func performAuthCodeFlowWithPKCE(t *testing.T, ts *TestServer, clientID, redirectURI, username, password, state, scope, nonce, codeChallenge, codeChallengeMethod string) string {
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

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + params.Encode()
	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "authorize page failed: %s", string(body))

	htmlBody := string(body)
	csrfToken := getCSRFToken(htmlBody)
	require.NotEmpty(t, csrfToken, "CSRF token not found")
	authorizeSig := getAuthorizeSig(htmlBody)

	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("redirect_uri", redirectURI)
	form.Set("state", state)
	form.Set("client_id", clientID)
	form.Set("scope", scope)
	form.Set("nonce", nonce)
	form.Set("code_challenge", codeChallenge)
	form.Set("code_challenge_method", codeChallengeMethod)
	form.Set("gorilla.csrf.Token", csrfToken)
	form.Set("authorize_sig", authorizeSig)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()
	require.Equal(t, http.StatusFound, loginResp.StatusCode, "login should redirect")

	location := loginResp.Header.Get("Location")
	require.NotEmpty(t, location)

	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code not found")
	return code
}

// exchangeCode exchanges an authorization code for tokens.
func exchangeCode(t *testing.T, ts *TestServer, code, redirectURI, clientID, codeVerifier string) *token.TokenResponse {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token exchange failed: %s", string(body))

	var tokenResp token.TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)
	return &tokenResp
}

// exchangeCodeExpectError exchanges a code and expects a specific error.
func exchangeCodeExpectError(t *testing.T, ts *TestServer, code, redirectURI, clientID, codeVerifier string, expectedStatus int, expectedError string) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, expectedStatus, resp.StatusCode, "unexpected status: %s", string(body))

	if expectedError != "" {
		var errResp map[string]any
		err = json.Unmarshal(body, &errResp)
		require.NoError(t, err)
		require.Equal(t, expectedError, errResp["error"], "unexpected error type: %s", string(body))
	}
}

// refreshTokens uses a refresh token to obtain new tokens.
func refreshTokens(t *testing.T, ts *TestServer, refreshToken, clientID string) *token.TokenResponse {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh failed: %s", string(body))

	var tokenResp token.TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)
	return &tokenResp
}

// refreshTokensExpectError refreshes and expects failure.
func refreshTokensExpectError(t *testing.T, ts *TestServer, refreshToken, clientID string, expectedStatus int) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, expectedStatus, resp.StatusCode)
}

// refreshTokensWithScope refreshes with an explicit scope parameter.
func refreshTokensWithScope(t *testing.T, ts *TestServer, refreshToken, clientID, scope string, expectedStatus int) (*token.TokenResponse, int) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	if scope != "" {
		form.Set("scope", scope)
	}

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}

	var tokenResp token.TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)
	return &tokenResp, resp.StatusCode
}
