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

// createConfidentialClient creates a confidential client with the given grant types via the admin API.
func createConfidentialClient(t *testing.T, ts *TestServer, adminToken, clientID, clientSecret string, grantTypes []string) {
	t.Helper()

	gt, _ := json.Marshal(grantTypes)
	body := map[string]interface{}{
		"client_id":                  clientID,
		"client_name":               clientID + " Client",
		"client_secret":             clientSecret,
		"client_type":               "confidential",
		"redirect_uris":             []string{"http://localhost:3000/callback"},
		"grant_types":               json.RawMessage(gt),
		"response_types":            []string{"code"},
		"scopes":                    "openid profile email read write",
		"token_endpoint_auth_method": "client_secret_basic",
	}
	bodyJSON, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/clients", strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "failed to create client: %s", string(respBody))
}

// obtainClientCredentialsToken gets an access token via client_credentials grant with Basic Auth.
func obtainClientCredentialsToken(t *testing.T, ts *TestServer, clientID, clientSecret, scope string) (*token.TokenResponse, int) {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := ts.Client.Do(req)
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

func TestClientCredentials_FullFlow(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "cc-admin", "password123", "ccadmin@example.com")

	createConfidentialClient(t, ts, adminToken, "cc-e2e-client", "cc-e2e-secret", []string{"client_credentials"})

	// Get token via client_credentials
	tokenResp, status := obtainClientCredentialsToken(t, ts, "cc-e2e-client", "cc-e2e-secret", "read write")
	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, tokenResp)
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Equal(t, "Bearer", tokenResp.TokenType)
	assert.Greater(t, tokenResp.ExpiresIn, 0)

	// RFC 6749 §4.4.3: no refresh token
	assert.Empty(t, tokenResp.RefreshToken)
	// No ID token
	assert.Empty(t, tokenResp.IDToken)

	// Introspect the token — should be active
	introspectResp := introspectToken(t, ts, tokenResp.AccessToken)
	assert.True(t, introspectResp.Active)
	assert.Equal(t, "read write", introspectResp.Scope)
}

func TestClientCredentials_TokenRevocation(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "cc-revoke-admin", "password123", "ccrevoke@example.com")

	createConfidentialClient(t, ts, adminToken, "cc-revoke-client", "secret", []string{"client_credentials"})

	tokenResp, status := obtainClientCredentialsToken(t, ts, "cc-revoke-client", "secret", "read")
	require.Equal(t, http.StatusOK, status)

	// Revoke the token (using the client that owns the token)
	form := url.Values{}
	form.Set("token", tokenResp.AccessToken)
	revokeReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/revoke", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeReq.SetBasicAuth("cc-revoke-client", "secret")
	resp, err := ts.Client.Do(revokeReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Introspect — should now be inactive
	introspectResp := introspectToken(t, ts, tokenResp.AccessToken)
	assert.False(t, introspectResp.Active)
}

func TestClientCredentials_BasicAuth(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "cc-basic-admin", "password123", "ccbasic@example.com")

	createConfidentialClient(t, ts, adminToken, "cc-basic-client", "basic-secret", []string{"client_credentials"})

	tokenResp, status := obtainClientCredentialsToken(t, ts, "cc-basic-client", "basic-secret", "read")
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, tokenResp.AccessToken)
}

func TestClientCredentials_SecretPost(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "cc-post-admin", "password123", "ccpost@example.com")

	createConfidentialClient(t, ts, adminToken, "cc-post-client", "post-secret", []string{"client_credentials"})

	// Use client_secret_post authentication (form params instead of Basic Auth)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "cc-post-client")
	form.Set("client_secret", "post-secret")
	form.Set("scope", "read")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "secret_post failed: %s", string(body))

	var tokenResp token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tokenResp))
	assert.NotEmpty(t, tokenResp.AccessToken)
}

func TestClientCredentials_ScopeValidation(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "cc-scope-admin", "password123", "ccscope@example.com")

	createConfidentialClient(t, ts, adminToken, "cc-scope-client", "secret", []string{"client_credentials"})

	// Request an invalid scope
	_, status := obtainClientCredentialsToken(t, ts, "cc-scope-client", "secret", "admin superuser")
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestClientCredentials_NoRefreshToken(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "cc-norefresh-admin", "password123", "ccnorefresh@example.com")

	createConfidentialClient(t, ts, adminToken, "cc-norefresh-client", "secret", []string{"client_credentials"})

	tokenResp, status := obtainClientCredentialsToken(t, ts, "cc-norefresh-client", "secret", "read")
	require.Equal(t, http.StatusOK, status)

	// RFC 6749 §4.4.3: refresh token SHOULD NOT be included
	assert.Empty(t, tokenResp.RefreshToken)
}

func TestClientCredentials_PublicClientRejected(t *testing.T) {
	ts := startTestServer(t)

	// The default test-client is public — try client_credentials with it
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "test-client")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Should fail — public clients can't use client_credentials
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// introspectToken is a helper to introspect a token and return the parsed response.
type introspectResponse struct {
	Active bool   `json:"active"`
	Scope  string `json:"scope"`
	Sub    string `json:"sub"`
}

func introspectToken(t *testing.T, ts *TestServer, accessToken string) introspectResponse {
	t.Helper()

	form := url.Values{}
	form.Set("token", accessToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/introspect", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("e2e-confidential", "e2e-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	var result introspectResponse
	require.NoError(t, json.Unmarshal(body, &result))
	return result
}
