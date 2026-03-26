package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/deletion"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/token"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// obtainAccessToken performs the full auth code flow and token exchange,
// returning the access token for the given user.
func obtainAccessToken(t *testing.T, ts *TestServer, username, password string) string {
	t.Helper()
	redirectURI := "http://localhost:3000/callback"
	code := performAuthorizationCodeFlow(t, ts, "test-client", redirectURI, username, password, "state-del")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "test-client")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token exchange failed: %s", string(body))

	var tokens token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tokens))
	return tokens.AccessToken
}

// TestDeletion_AdminApprovalFlow: user submits a deletion request, admin lists it,
// admin approves it, and the user record is gone.
func TestDeletion_AdminApprovalFlow(t *testing.T) {
	ts := startTestServer(t)

	// Create regular user and get access token
	username := "del-user@test.com"
	password := "password123"
	usr := createTestUser(t, username, password, username)
	accessToken := obtainAccessToken(t, ts, username, password)

	// Create admin
	_, adminToken := createTestAdmin(t, ts, "del-admin@test.com", "adminpass123", "del-admin@test.com")

	// 1. GET deletion-request — none pending
	req, err := http.NewRequest("GET", ts.BaseURL+"/account/api/deletion-request", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 2. POST deletion-request with reason
	body, _ := json.Marshal(map[string]string{"reason": "e2e test"})
	req, err = http.NewRequest("POST", ts.BaseURL+"/account/api/deletion-request", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "request deletion failed: %s", string(respBody))

	var drResp model.ApiResponse[deletion.DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(respBody, &drResp))
	assert.Equal(t, usr.ID, drResp.Data.UserID)
	require.NotNil(t, drResp.Data.Reason)
	assert.Equal(t, "e2e test", *drResp.Data.Reason)
	requestID := drResp.Data.ID

	// 3. POST again — should conflict
	req, err = http.NewRequest("POST", ts.BaseURL+"/account/api/deletion-request", bytes.NewBuffer([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	// 4. Admin lists deletion requests
	req, err = http.NewRequest("GET", ts.BaseURL+"/admin/api/deletion-requests", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ = io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "list deletion requests failed: %s", string(respBody))

	var listResp model.ApiResponse[[]deletion.DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(respBody, &listResp))
	require.Len(t, listResp.Data, 1)
	assert.Equal(t, requestID, listResp.Data[0].ID)

	// 5. Admin approves the request
	req, err = http.NewRequest("POST", ts.BaseURL+"/admin/api/deletion-requests/"+requestID+"/approve", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// 6. Verify user is gone — profile endpoint should 401
	req, err = http.NewRequest("GET", ts.BaseURL+"/account/api/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// 7. Deletion requests list is now empty
	req, err = http.NewRequest("GET", ts.BaseURL+"/admin/api/deletion-requests", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ = io.ReadAll(resp.Body)
	var listRespAfter model.ApiResponse[[]deletion.DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(respBody, &listRespAfter))
	assert.Empty(t, listRespAfter.Data)
}

// TestDeletion_SelfServiceFlow: with self-service enabled, user deletes their own account immediately.
func TestDeletion_SelfServiceFlow(t *testing.T) {
	ts := startTestServer(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowSelfServiceDeletion = true
	})

	username := "selfdelete@test.com"
	password := "password123"
	createTestUser(t, username, password, username)
	accessToken := obtainAccessToken(t, ts, username, password)

	// POST deletion-request — self-service mode deletes immediately
	req, err := http.NewRequest("POST", ts.BaseURL+"/account/api/deletion-request", bytes.NewBuffer([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Verify user is gone
	req, err = http.NewRequest("GET", ts.BaseURL+"/account/api/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDeletion_CancelRequest: user submits a request then cancels it.
func TestDeletion_CancelRequest(t *testing.T) {
	ts := startTestServer(t)

	username := "canceldelete@test.com"
	password := "password123"
	createTestUser(t, username, password, username)
	accessToken := obtainAccessToken(t, ts, username, password)

	// Submit deletion request
	req, err := http.NewRequest("POST", ts.BaseURL+"/account/api/deletion-request", bytes.NewBuffer([]byte(`{"reason":"changed my mind"}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Cancel it
	req, err = http.NewRequest("DELETE", ts.BaseURL+"/account/api/deletion-request", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Verify no pending request
	req, err = http.NewRequest("GET", ts.BaseURL+"/account/api/deletion-request", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var drResp model.ApiResponse[*deletion.DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(respBody, &drResp))
	assert.Nil(t, drResp.Data)

	// Profile still accessible — user account intact
	req, err = http.NewRequest("GET", ts.BaseURL+"/account/api/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestDeletion_AdminCancelRequest: admin dismisses a deletion request without deleting the user.
func TestDeletion_AdminCancelRequest(t *testing.T) {
	ts := startTestServer(t)

	username := "admcancel@test.com"
	password := "password123"
	createTestUser(t, username, password, username)
	accessToken := obtainAccessToken(t, ts, username, password)
	_, adminToken := createTestAdmin(t, ts, "admcancel-admin@test.com", "adminpass123", "admcancel-admin@test.com")

	// User submits request
	req, err := http.NewRequest("POST", ts.BaseURL+"/account/api/deletion-request", bytes.NewBuffer([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var drResp model.ApiResponse[deletion.DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(respBody, &drResp))
	requestID := drResp.Data.ID

	// Admin dismisses it
	req, err = http.NewRequest("DELETE", ts.BaseURL+"/admin/api/deletion-requests/"+requestID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// User still exists and profile is accessible
	req, err = http.NewRequest("GET", ts.BaseURL+"/account/api/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
