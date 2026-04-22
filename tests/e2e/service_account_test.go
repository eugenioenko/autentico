package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createAdminServiceAccountClient registers a confidential client with the
// is_admin_service_account flag enabled, the client_credentials grant, and the
// autentico-admin audience — the minimum required to use it as a headless
// admin credential.
func createAdminServiceAccountClient(t *testing.T, ts *TestServer, adminToken, clientID, clientSecret string) {
	t.Helper()

	body := map[string]interface{}{
		"client_id":                  clientID,
		"client_name":                "Admin Service " + clientID,
		"client_secret":              clientSecret,
		"client_type":                "confidential",
		"redirect_uris":              []string{"http://localhost:3000/callback"},
		"grant_types":                []string{"client_credentials"},
		"response_types":             []string{"code"},
		"scopes":                     "openid profile email read write",
		"token_endpoint_auth_method": "client_secret_basic",
		"allowed_audiences":          []string{"autentico-admin"},
		"is_admin_service_account":   true,
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
	require.Equal(t, http.StatusCreated, resp.StatusCode, "failed to create service-account client: %s", string(respBody))
}

// TestAdminServiceAccount_FullFlow exercises the end-to-end service-account
// path: create → obtain token via client_credentials → call admin API → 200.
// This is the primary happy-path test for the feature.
func TestAdminServiceAccount_FullFlow(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "svc-admin", "password123", "svcadmin@example.com")

	createAdminServiceAccountClient(t, ts, adminToken, "svc-acc-client", "svc-acc-secret")

	// Obtain a token via client_credentials
	tokenResp, status := obtainClientCredentialsToken(t, ts, "svc-acc-client", "svc-acc-secret", "read")
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, tokenResp)
	require.NotEmpty(t, tokenResp.AccessToken)

	// Call the admin API with the service-account token
	req, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/clients", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "service-account token should be accepted by admin API: %s", string(body))
}

// TestAdminServiceAccount_WithoutFlag_Rejected verifies that a regular
// confidential client that happens to have autentico-admin in aud but does NOT
// have the is_admin_service_account flag is rejected by the admin API.
// This is the guard that prevents accidental elevation.
func TestAdminServiceAccount_WithoutFlag_Rejected(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "svc-noflag-admin", "password123", "svcnoflag@example.com")

	// Client with autentico-admin in aud but NO is_admin_service_account flag.
	body := map[string]interface{}{
		"client_id":                  "svc-noflag-client",
		"client_name":                "No Flag Client",
		"client_secret":              "no-flag-secret",
		"client_type":                "confidential",
		"redirect_uris":              []string{"http://localhost:3000/callback"},
		"grant_types":                []string{"client_credentials"},
		"response_types":             []string{"code"},
		"scopes":                     "openid profile email read",
		"token_endpoint_auth_method": "client_secret_basic",
		"allowed_audiences":          []string{"autentico-admin"},
	}
	bodyJSON, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/clients", strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Obtain a client_credentials token
	tokenResp, status := obtainClientCredentialsToken(t, ts, "svc-noflag-client", "no-flag-secret", "read")
	require.Equal(t, http.StatusOK, status)

	// Call the admin API — must be rejected.
	adminReq, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/clients", nil)
	require.NoError(t, err)
	adminReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	adminResp, err := ts.Client.Do(adminReq)
	require.NoError(t, err)
	defer func() { _ = adminResp.Body.Close() }()

	// Without the flag, the middleware falls through to the user-based check;
	// the token's sub (= client_id) does not match any user, so it 401s with
	// "User not found".
	assert.NotEqual(t, http.StatusOK, adminResp.StatusCode,
		"client_credentials token without is_admin_service_account flag must not access admin API")
}

// TestAdminServiceAccount_PublicClient_Rejected verifies that creating a
// public client with the flag set is rejected by validation.
func TestAdminServiceAccount_PublicClient_Rejected(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "svc-public-admin", "password123", "svcpublic@example.com")

	body := map[string]interface{}{
		"client_name":              "Public Svc",
		"client_type":              "public",
		"redirect_uris":            []string{"http://localhost:3000/callback"},
		"grant_types":              []string{"client_credentials"},
		"is_admin_service_account": true,
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
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected 400: %s", string(respBody))
	assert.Contains(t, string(respBody), "confidential")
}
