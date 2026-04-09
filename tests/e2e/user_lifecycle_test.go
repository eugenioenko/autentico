package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helpers ---

// adminDeactivateUser calls POST /admin/api/users/{id}/deactivate.
func adminDeactivateUser(t *testing.T, ts *TestServer, adminToken, userID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/users/"+userID+"/deactivate", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	return resp
}

// adminReactivateUser calls POST /admin/api/users/{id}/reactivate.
func adminReactivateUser(t *testing.T, ts *TestServer, adminToken, userID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/users/"+userID+"/reactivate", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	return resp
}

// adminHardDeleteUser calls DELETE /admin/api/users/{id}.
func adminHardDeleteUser(t *testing.T, ts *TestServer, adminToken, userID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("DELETE", ts.BaseURL+"/admin/api/users/"+userID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	return resp
}

// introspectTokenWithBasicAuth introspects a token using client credentials.
func introspectTokenWithBasicAuth(t *testing.T, ts *TestServer, accessToken string) map[string]interface{} {
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
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &result))
	return result
}

// getGroupMembers returns the member list for a group.
func getGroupMembers(t *testing.T, ts *TestServer, adminToken, groupID string) []group.GroupMemberResponse {
	t.Helper()
	req, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/groups/"+groupID+"/members", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result model.ApiResponse[[]group.GroupMemberResponse]
	require.NoError(t, json.Unmarshal(body, &result))
	return result.Data
}

// --- Deactivation Tests ---

func TestDeactivate_TokensInvalidated(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "deact-introspect@test.com", "password123", "deact-introspect@test.com")
	// Issue token via e2e-confidential so the introspect calls use the same client
	tokens := obtainTokensViaConfidentialClient(t, ts, "deact-introspect@test.com", "password123")
	_, adminToken := createTestAdmin(t, ts, "deact-admin1@test.com", "adminpass123", "deact-admin1@test.com")

	// Token should be active before deactivation
	result := introspectTokenWithBasicAuth(t, ts, tokens.AccessToken)
	assert.Equal(t, true, result["active"])

	// Deactivate user
	resp := adminDeactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Token should now be inactive
	result = introspectTokenWithBasicAuth(t, ts, tokens.AccessToken)
	assert.Equal(t, false, result["active"])
}

func TestDeactivate_LoginBlocked(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "deact-login@test.com", "password123", "deact-login@test.com")
	_, adminToken := createTestAdmin(t, ts, "deact-admin2@test.com", "adminpass123", "deact-admin2@test.com")

	// Deactivate user
	resp := adminDeactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Attempting login via password grant should fail
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "deact-login@test.com")
	form.Set("password", "password123")

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()
	assert.NotEqual(t, http.StatusOK, tokenResp.StatusCode, "deactivated user should not be able to login")
}

func TestDeactivate_AlreadyDeactivated(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "deact-twice@test.com", "password123", "deact-twice@test.com")
	_, adminToken := createTestAdmin(t, ts, "deact-admin3@test.com", "adminpass123", "deact-admin3@test.com")

	// First deactivation succeeds
	resp := adminDeactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Second deactivation fails
	resp2 := adminDeactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

func TestDeactivate_GroupMembersFiltered(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "deact-group@test.com", "password123", "deact-group@test.com")
	_, adminToken := createTestAdmin(t, ts, "deact-admin4@test.com", "adminpass123", "deact-admin4@test.com")

	// Create group and add user
	g := adminCreateGroup(t, ts, adminToken, "deact-test-group", "test")
	adminAddMember(t, ts, adminToken, g.ID, usr.ID)

	// User should be in group
	members := getGroupMembers(t, ts, adminToken, g.ID)
	assert.Len(t, members, 1)

	// Deactivate user
	resp := adminDeactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Deactivated user should not appear in group members
	members = getGroupMembers(t, ts, adminToken, g.ID)
	assert.Empty(t, members)
}

// --- Reactivation Tests ---

func TestReactivate_LoginWorksAgain(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "react-login@test.com", "password123", "react-login@test.com")
	_, adminToken := createTestAdmin(t, ts, "react-admin1@test.com", "adminpass123", "react-admin1@test.com")

	// Deactivate
	resp := adminDeactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Verify login fails
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "react-login@test.com")
	form.Set("password", "password123")

	tokenResp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()
	require.NotEqual(t, http.StatusOK, tokenResp.StatusCode)

	// Reactivate
	resp2 := adminReactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp2.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp2.StatusCode)

	// Login should work again
	tokenResp2, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = tokenResp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, tokenResp2.StatusCode)
}

func TestReactivate_NotDeactivatedUser(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "react-notdeact@test.com", "password123", "react-notdeact@test.com")
	_, adminToken := createTestAdmin(t, ts, "react-admin2@test.com", "adminpass123", "react-admin2@test.com")

	// Reactivating a user that isn't deactivated should fail
	resp := adminReactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Hard Delete Tests ---

func TestHardDelete_UserGone(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "harddelete@test.com", "password123", "harddelete@test.com")
	accessToken := obtainAccessToken(t, ts, "harddelete@test.com", "password123")
	_, adminToken := createTestAdmin(t, ts, "hd-admin1@test.com", "adminpass123", "hd-admin1@test.com")

	// Delete user
	resp := adminHardDeleteUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Token should be inactive (user gone)
	result := introspectTokenWithBasicAuth(t, ts, accessToken)
	assert.Equal(t, false, result["active"])

	// User should not be found via admin API
	req, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/users/"+usr.ID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp2, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

func TestHardDelete_UsernameFreed(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "reusable@test.com", "password123", "reusable@test.com")
	_, adminToken := createTestAdmin(t, ts, "hd-admin2@test.com", "adminpass123", "hd-admin2@test.com")

	// Delete user
	resp := adminHardDeleteUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Can create a new user with the same username/email
	newUsr := createTestUser(t, "reusable@test.com", "newpass123", "reusable@test.com")
	assert.NotEqual(t, usr.ID, newUsr.ID)
}

func TestHardDelete_GroupMembershipCleanedUp(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "hd-group@test.com", "password123", "hd-group@test.com")
	_, adminToken := createTestAdmin(t, ts, "hd-admin3@test.com", "adminpass123", "hd-admin3@test.com")

	// Create group and add user
	g := adminCreateGroup(t, ts, adminToken, "hd-test-group", "test")
	adminAddMember(t, ts, adminToken, g.ID, usr.ID)

	members := getGroupMembers(t, ts, adminToken, g.ID)
	require.Len(t, members, 1)

	// Hard-delete user
	resp := adminHardDeleteUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Group should have no members
	members = getGroupMembers(t, ts, adminToken, g.ID)
	assert.Empty(t, members)
}

func TestHardDelete_NonExistentUser(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "hd-admin4@test.com", "adminpass123", "hd-admin4@test.com")

	resp := adminHardDeleteUser(t, ts, adminToken, "nonexistent-id")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHardDelete_DeactivatedUser(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "hd-deact@test.com", "password123", "hd-deact@test.com")
	_, adminToken := createTestAdmin(t, ts, "hd-admin5@test.com", "adminpass123", "hd-admin5@test.com")

	// Deactivate first
	resp := adminDeactivateUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Then hard-delete — should work even on deactivated users
	resp2 := adminHardDeleteUser(t, ts, adminToken, usr.ID)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp2.StatusCode)

	// Username should be freed
	newUsr := createTestUser(t, "hd-deact@test.com", "newpass", "hd-deact@test.com")
	assert.NotEmpty(t, newUsr.ID)
}

// --- Self-Service Deletion Tests ---

func TestSelfDelete_WhenEnabled(t *testing.T) {
	ts := startTestServer(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowSelfServiceDeletion = true
	})

	createTestUser(t, "selfdelete2@test.com", "password123", "selfdelete2@test.com")
	accessToken := obtainAccessToken(t, ts, "selfdelete2@test.com", "password123")

	// Self-delete via deletion-request endpoint
	req, err := http.NewRequest("POST", ts.BaseURL+"/account/api/deletion-request", strings.NewReader(`{}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Profile should be inaccessible
	req, err = http.NewRequest("GET", ts.BaseURL+"/account/api/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
