package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpiredAccessToken_UserInfoRejects(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAccessTokenExpiration = 1 * time.Second

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Wait for the access token JWT to expire
	time.Sleep(2 * time.Second)

	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "expired token should be rejected by userinfo")
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Bearer", "RFC 6750 §3: WWW-Authenticate must be present on 401")
}

func TestExpiredAccessToken_IntrospectRejects(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthAccessTokenExpiration = 1 * time.Second

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	time.Sleep(2 * time.Second)

	body, _ := json.Marshal(map[string]string{"token": tokens.AccessToken})
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/introspect", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("e2e-confidential", "e2e-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// RFC 7662 §2.2: expired token → 200 {"active":false}, not 401
	assert.Equal(t, http.StatusOK, resp.StatusCode, "RFC 7662 §2.2: expired token must return 200 with active=false")
	var result map[string]interface{}
	body2, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body2, &result)
	assert.Equal(t, false, result["active"], "active must be false for expired token")
}

func TestRevokedToken_UserInfoRejects(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Revoke the token
	form := url.Values{}
	form.Set("token", tokens.AccessToken)
	revokeResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/revoke", form)
	require.NoError(t, err)
	defer func() { _ = revokeResp.Body.Close() }()
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Call userinfo with revoked token
	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "revoked token should be rejected by userinfo")
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Bearer", "RFC 6750 §3: WWW-Authenticate must be present on 401")
}

func TestRevokedToken_IntrospectRejects(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Revoke the token
	form := url.Values{}
	form.Set("token", tokens.AccessToken)
	revokeResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/revoke", form)
	require.NoError(t, err)
	defer func() { _ = revokeResp.Body.Close() }()

	// Introspect the revoked token
	body, _ := json.Marshal(map[string]string{"token": tokens.AccessToken})
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/introspect", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("e2e-confidential", "e2e-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// RFC 7662 §2.2: revoked token → 200 {"active":false}, not 401
	assert.Equal(t, http.StatusOK, resp.StatusCode, "RFC 7662 §2.2: revoked token must return 200 with active=false")
	var result map[string]interface{}
	respBody, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(respBody, &result)
	assert.Equal(t, false, result["active"], "active must be false for revoked token")
}

func TestRevokedToken_RefreshRejects(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Revoke the token
	form := url.Values{}
	form.Set("token", tokens.AccessToken)
	revokeResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/revoke", form)
	require.NoError(t, err)
	defer func() { _ = revokeResp.Body.Close() }()

	// Attempt refresh with the revoked token's refresh_token
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tokens.RefreshToken)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", refreshForm)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "revoked token's refresh should be rejected: %s", string(body))
}

func TestRefreshToken_RotationBehavior(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Refresh to get new tokens
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tokens.RefreshToken)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh should succeed: %s", string(body))

	var newTokens token.TokenResponse
	err = json.Unmarshal(body, &newTokens)
	require.NoError(t, err)

	assert.NotEmpty(t, newTokens.AccessToken)
	assert.NotEqual(t, tokens.AccessToken, newTokens.AccessToken, "new access token should differ from old")

	// Verify new access token works at /oauth2/userinfo
	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+newTokens.AccessToken)

	userinfoResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = userinfoResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, userinfoResp.StatusCode, "new access token should work at userinfo")
}

func TestRefreshToken_ExpiredRefresh(t *testing.T) {
	ts := startTestServer(t)
	config.Values.AuthRefreshTokenExpiration = 1 * time.Second

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Wait for the refresh token to expire
	time.Sleep(2 * time.Second)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tokens.RefreshToken)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "expired refresh token should be rejected")
}

func TestRefreshToken_InvalidRefreshToken(t *testing.T) {
	ts := startTestServer(t)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "totally-invalid-random-string")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "invalid refresh token should be rejected")
}

func TestRefreshToken_AfterLogout(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Logout via POST with id_token_hint to deactivate the session
	logoutForm := url.Values{"id_token_hint": {tokens.AccessToken}}
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/logout", strings.NewReader(logoutForm.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	logoutResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = logoutResp.Body.Close() }()
	require.Equal(t, http.StatusOK, logoutResp.StatusCode)

	// Attempt refresh — session is deactivated, should be rejected
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tokens.RefreshToken)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "refresh after logout should be rejected: %s", string(body))
}
