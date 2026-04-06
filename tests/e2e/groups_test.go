package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Admin API helpers ---

func adminCreateGroup(t *testing.T, ts *TestServer, adminToken, name, description string) group.GroupResponse {
	t.Helper()
	body, _ := json.Marshal(group.GroupCreateRequest{Name: name, Description: description})
	req, _ := http.NewRequest("POST", ts.BaseURL+"/admin/api/groups", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create group failed: %s", string(respBody))
	var result model.ApiResponse[group.GroupResponse]
	require.NoError(t, json.Unmarshal(respBody, &result))
	return result.Data
}

func adminAddMember(t *testing.T, ts *TestServer, adminToken, groupID, userID string) {
	t.Helper()
	body, _ := json.Marshal(group.GroupMemberRequest{UserID: userID})
	req, _ := http.NewRequest("POST", ts.BaseURL+"/admin/api/groups/"+groupID+"/members", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "add member failed: %s", string(respBody))
}

// --- Group CRUD tests ---

func TestGroupCRUD(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "grpadmin", "password123", "grpadmin@test.com")

	// Create
	g := adminCreateGroup(t, ts, adminToken, "test-group", "A test group")
	assert.NotEmpty(t, g.ID)
	assert.Equal(t, "test-group", g.Name)
	assert.Equal(t, "A test group", g.Description)

	// Get
	req, _ := http.NewRequest("GET", ts.BaseURL+"/admin/api/groups/"+g.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var getResp model.ApiResponse[group.GroupResponse]
	body, _ := io.ReadAll(resp.Body)
	require.NoError(t, json.Unmarshal(body, &getResp))
	assert.Equal(t, "test-group", getResp.Data.Name)

	// Update
	updateBody, _ := json.Marshal(group.GroupUpdateRequest{Name: "renamed-group"})
	req, _ = http.NewRequest("PUT", ts.BaseURL+"/admin/api/groups/"+g.ID, strings.NewReader(string(updateBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp2, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// List
	req, _ = http.NewRequest("GET", ts.BaseURL+"/admin/api/groups", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp3, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	body3, _ := io.ReadAll(resp3.Body)
	var listResp model.ApiResponse[[]group.GroupResponse]
	require.NoError(t, json.Unmarshal(body3, &listResp))
	assert.Len(t, listResp.Data, 1)
	assert.Equal(t, "renamed-group", listResp.Data[0].Name)

	// Delete
	req, _ = http.NewRequest("DELETE", ts.BaseURL+"/admin/api/groups/"+g.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp4, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp4.StatusCode)

	// Verify deleted
	req, _ = http.NewRequest("GET", ts.BaseURL+"/admin/api/groups/"+g.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp5, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp5.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp5.StatusCode)
}

func TestGroupMembership(t *testing.T) {
	ts := startTestServer(t)
	admin, adminToken := createTestAdmin(t, ts, "memadmin", "password123", "memadmin@test.com")
	usr := createTestUser(t, "memuser", "password123", "memuser@test.com")

	g := adminCreateGroup(t, ts, adminToken, "devs", "")

	// Add member
	adminAddMember(t, ts, adminToken, g.ID, usr.ID)

	// List members
	req, _ := http.NewRequest("GET", ts.BaseURL+"/admin/api/groups/"+g.ID+"/members", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var membersResp model.ApiResponse[[]group.GroupMemberResponse]
	require.NoError(t, json.Unmarshal(body, &membersResp))
	assert.Len(t, membersResp.Data, 1)
	assert.Equal(t, usr.ID, membersResp.Data[0].UserID)

	// Get user groups
	req, _ = http.NewRequest("GET", ts.BaseURL+"/admin/api/users/"+usr.ID+"/groups", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp2, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	body2, _ := io.ReadAll(resp2.Body)
	var userGroupsResp model.ApiResponse[[]group.GroupResponse]
	require.NoError(t, json.Unmarshal(body2, &userGroupsResp))
	assert.Len(t, userGroupsResp.Data, 1)
	assert.Equal(t, "devs", userGroupsResp.Data[0].Name)

	// Remove member
	req, _ = http.NewRequest("DELETE", ts.BaseURL+"/admin/api/groups/"+g.ID+"/members/"+usr.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp3, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	// Verify removed
	req, _ = http.NewRequest("GET", ts.BaseURL+"/admin/api/groups/"+g.ID+"/members", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp4, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp4.Body.Close() }()
	body4, _ := io.ReadAll(resp4.Body)
	var emptyMembers model.ApiResponse[[]group.GroupMemberResponse]
	require.NoError(t, json.Unmarshal(body4, &emptyMembers))
	assert.Empty(t, emptyMembers.Data)

	_ = admin // suppress unused
}

func TestGroupsClaimInToken(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "tokadmin", "password123", "tokadmin@test.com")

	// Create user and group, add membership
	usr := createTestUser(t, "tokuser", "password123", "tokuser@test.com")
	g := adminCreateGroup(t, ts, adminToken, "engineers", "")
	adminAddMember(t, ts, adminToken, g.ID, usr.ID)

	// Authenticate with groups scope via password grant
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "tokuser")
	form.Set("password", "password123")
	form.Set("scope", "openid groups")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token request failed: %s", string(body))

	var tokenResp token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tokenResp))

	// Decode ID token and verify groups claim
	claims := decodeJWTPayload(t, tokenResp.IDToken)
	groupsClaim, ok := claims["groups"].([]interface{})
	require.True(t, ok, "groups claim must be an array in ID token")
	assert.Contains(t, groupsClaim, "engineers")

	// Also verify access token
	atClaims := decodeJWTPayload(t, tokenResp.AccessToken)
	atGroups, ok := atClaims["groups"].([]interface{})
	require.True(t, ok, "groups claim must be an array in access token")
	assert.Contains(t, atGroups, "engineers")
}

func TestGroupsClaimInUserinfo(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "uiadmin", "password123", "uiadmin@test.com")

	usr := createTestUser(t, "uiuser", "password123", "uiuser@test.com")
	g := adminCreateGroup(t, ts, adminToken, "designers", "")
	adminAddMember(t, ts, adminToken, g.ID, usr.ID)

	// Get token with groups scope
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "uiuser")
	form.Set("password", "password123")
	form.Set("scope", "openid groups")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tokenResp))

	// Call userinfo
	req, _ := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	uiResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = uiResp.Body.Close() }()
	uiBody, _ := io.ReadAll(uiResp.Body)
	require.Equal(t, http.StatusOK, uiResp.StatusCode)

	var userinfo map[string]interface{}
	require.NoError(t, json.Unmarshal(uiBody, &userinfo))

	groupsClaim, ok := userinfo["groups"].([]interface{})
	require.True(t, ok, "groups must be in userinfo response")
	assert.Contains(t, groupsClaim, "designers")
}

func TestGroupsClaimWithoutScope(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "nsadmin", "password123", "nsadmin@test.com")

	usr := createTestUser(t, "nsuser", "password123", "nsuser@test.com")
	g := adminCreateGroup(t, ts, adminToken, "ops", "")
	adminAddMember(t, ts, adminToken, g.ID, usr.ID)

	// Authenticate WITHOUT groups scope
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "nsuser")
	form.Set("password", "password123")
	form.Set("scope", "openid profile")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tokenResp))

	// ID token should NOT have groups claim
	claims := decodeJWTPayload(t, tokenResp.IDToken)
	assert.Nil(t, claims["groups"], "groups claim must not be present without groups scope")

	// Access token should NOT have groups claim
	atClaims := decodeJWTPayload(t, tokenResp.AccessToken)
	assert.Nil(t, atClaims["groups"], "groups claim must not be in access token without groups scope")

	// Userinfo should NOT have groups
	req, _ := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	uiResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = uiResp.Body.Close() }()
	uiBody, _ := io.ReadAll(uiResp.Body)
	var userinfo map[string]interface{}
	require.NoError(t, json.Unmarshal(uiBody, &userinfo))
	assert.Nil(t, userinfo["groups"], "groups must not be in userinfo without groups scope")
}

func TestGroupsClaimUserNoGroups(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "nogrpuser", "password123", "nogrpuser@test.com")

	// Authenticate with groups scope but user has no groups
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "nogrpuser")
	form.Set("password", "password123")
	form.Set("scope", "openid groups")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tokenResp))

	// groups claim should be absent (not an empty array)
	claims := decodeJWTPayload(t, tokenResp.IDToken)
	assert.Nil(t, claims["groups"], "groups claim must be omitted when user has no groups")

	atClaims := decodeJWTPayload(t, tokenResp.AccessToken)
	assert.Nil(t, atClaims["groups"], "groups claim must be omitted in access token when user has no groups")
}
