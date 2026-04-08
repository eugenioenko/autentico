package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordGrant_RefreshAsJSON(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "user@test.com")
	form.Set("password", "password123")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token request failed: %s", string(body))

	var tokenResp token.TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.NotEmpty(t, tokenResp.RefreshToken)
}

func TestPasswordGrant_RefreshTokenRotation(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Get initial tokens
	tokenResp := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")
	require.NotEmpty(t, tokenResp.RefreshToken)

	// Refresh
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tokenResp.RefreshToken)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh failed: %s", string(body))

	var refreshResp token.TokenResponse
	err = json.Unmarshal(body, &refreshResp)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshResp.AccessToken)
	assert.NotEmpty(t, refreshResp.TokenType)
}

func TestRevokeToken_E2E(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	tokenResp := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	form := url.Values{}
	form.Set("token", tokenResp.AccessToken)

	resp, err := revokeToken(t, ts, form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestUserInfo_E2E(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "user@test.com", "password123", "user@test.com")

	tokenResp := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "userinfo failed: %s", string(body))

	var userInfo map[string]interface{}
	err = json.Unmarshal(body, &userInfo)
	require.NoError(t, err)
	assert.Equal(t, usr.ID, userInfo["sub"])
}

func TestLogout_E2E(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	tokenResp := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	form := url.Values{}
	form.Set("id_token_hint", tokenResp.AccessToken)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/logout", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "signed out")
}

func TestAuthorize_RendersLoginPage(t *testing.T) {
	ts := startTestServer(t)

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"scope":                 {"openid"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	doc := string(body)
	assert.Contains(t, doc, "http://localhost:3000/callback")
	assert.Contains(t, doc, "<body id=\"autentico\">")
}

func TestAuthorize_InvalidRequest(t *testing.T) {
	ts := startTestServer(t)

	// Missing redirect_uri — cannot redirect back, shows HTML error page
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "Invalid redirect_uri")
}

func TestWellKnown_ReturnsDiscoveryDocument(t *testing.T) {
	ts := startTestServer(t)

	resp, err := ts.Client.Get(ts.BaseURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var cfg map[string]interface{}
	err = json.Unmarshal(body, &cfg)
	require.NoError(t, err)

	// Verify key fields are present
	assert.Contains(t, cfg, "issuer")
	assert.Contains(t, cfg, "authorization_endpoint")
	assert.Contains(t, cfg, "token_endpoint")
	assert.Contains(t, cfg, "jwks_uri")
	assert.Contains(t, cfg, "userinfo_endpoint")
}

func TestWellKnown_AcrValuesSupported(t *testing.T) {
	ts := startTestServer(t)

	resp, err := ts.Client.Get(ts.BaseURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var cfg map[string]interface{}
	err = json.Unmarshal(body, &cfg)
	require.NoError(t, err)

	// acr_values_supported must include "1"
	acr, ok := cfg["acr_values_supported"].([]interface{})
	require.True(t, ok, "acr_values_supported should be an array")
	assert.Contains(t, acr, "1")

	// claims_supported must include "acr"
	claims, ok := cfg["claims_supported"].([]interface{})
	require.True(t, ok, "claims_supported should be an array")
	assert.Contains(t, claims, "acr")
}

func TestPasswordGrant_InvalidCredentials(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "user@test.com")
	form.Set("password", "wrongpassword")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "invalid")
}

func TestRefreshToken_AfterRevoke(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	tokenResp := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Revoke the access token
	revokeForm := url.Values{}
	revokeForm.Set("token", tokenResp.AccessToken)

	revokeResp, err := revokeToken(t, ts, revokeForm)
	require.NoError(t, err)
	_ = revokeResp.Body.Close()
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Try to use userinfo with revoked token
	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogout_InvalidatesRefresh(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	tokenResp := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Logout
	logoutForm := url.Values{}
	logoutForm.Set("id_token_hint", tokenResp.AccessToken)

	logoutResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/logout", logoutForm)
	require.NoError(t, err)
	_ = logoutResp.Body.Close()
	require.Equal(t, http.StatusOK, logoutResp.StatusCode)

	// Try to refresh — should fail
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tokenResp.RefreshToken)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", refreshForm)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIntrospect_ActiveToken(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "user@test.com", "password123", "user@test.com")

	tokenResp := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	form := url.Values{}
	form.Set("token", tokenResp.AccessToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/introspect", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("e2e-confidential", "e2e-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)
	assert.Equal(t, true, result["active"])
}
