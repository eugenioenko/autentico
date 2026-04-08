package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountAPI_ProfileLifecycle(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	// 1. Create user
	username := "account-user@test.com"
	password := "password123"
	createTestUser(t, username, password, username)

	// 2. Perform login flow to get an access token
	code := performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, username, password, "state123")

	// 3. Exchange code for tokens
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", testCodeVerifier)

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	body, _ := io.ReadAll(tokenResp.Body)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)

	accessToken := tokens.AccessToken

	// 4. GET /account/api/profile
	req, err := http.NewRequest("GET", ts.BaseURL+"/account/api/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var profileResp model.ApiResponse[user.UserResponse]
	err = json.Unmarshal(body, &profileResp)
	require.NoError(t, err, "failed to unmarshal: %s", string(body))
	assert.Equal(t, username, profileResp.Data.Username)

	// 5. PUT /account/api/profile (Update)
	updateReq := user.UserUpdateRequest{
		GivenName: "NewGivenName",
		FamilyName: "NewFamilyName",
	}
	updateBody, _ := json.Marshal(updateReq)
	
	req, err = http.NewRequest("PUT", ts.BaseURL+"/account/api/profile", bytes.NewBuffer(updateBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = json.Unmarshal(body, &profileResp)
	require.NoError(t, err)
	assert.Equal(t, "NewGivenName", profileResp.Data.GivenName)
	assert.Equal(t, "NewFamilyName", profileResp.Data.FamilyName)

	// 6. Verify with another GET
	req, err = http.NewRequest("GET", ts.BaseURL+"/account/api/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ = io.ReadAll(resp.Body)
	err = json.Unmarshal(body, &profileResp)
	require.NoError(t, err)
	assert.Equal(t, "NewGivenName", profileResp.Data.GivenName)
}
