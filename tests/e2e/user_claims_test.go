package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/userclaim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func adminUpsertClaim(t *testing.T, ts *TestServer, adminToken, userID, name, value string) {
	t.Helper()
	body, _ := json.Marshal(userclaim.UserClaimRequest{Name: name, Value: value})
	req, _ := http.NewRequest("POST", ts.BaseURL+"/admin/api/users/"+userID+"/claims", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "upsert claim failed: %s", string(respBody))
}

func passwordToken(t *testing.T, ts *TestServer, username, password, scope string) token.TokenResponse {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", scope)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token request failed: %s", string(body))
	var tr token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tr))
	return tr
}

func TestUserClaims_AdminCRUD(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ccadmin", "password123", "ccadmin@test.com")
	usr := createTestUser(t, "cccruduser", "password123", "cccrud@test.com")

	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "gold")
	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "platinum") // upsert

	// List
	req, _ := http.NewRequest("GET", ts.BaseURL+"/admin/api/users/"+usr.ID+"/claims", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var listResp model.ApiResponse[[]userclaim.UserClaimResponse]
	require.NoError(t, json.Unmarshal(body, &listResp))
	require.Len(t, listResp.Data, 1)
	assert.Equal(t, "tier", listResp.Data[0].Name)
	assert.Equal(t, "platinum", listResp.Data[0].Value)

	// Reserved name rejected
	rb, _ := json.Marshal(userclaim.UserClaimRequest{Name: "email", Value: "x"})
	req, _ = http.NewRequest("POST", ts.BaseURL+"/admin/api/users/"+usr.ID+"/claims", strings.NewReader(string(rb)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp2, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)

	// Delete
	req, _ = http.NewRequest("DELETE", ts.BaseURL+"/admin/api/users/"+usr.ID+"/claims/tier", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp3, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp3.StatusCode)
}

// TestUserClaims_DeleteNamespacedName exercises the {name...} route through the
// real mux: a namespaced claim name contains "//", which net/http.ServeMux
// path-cleans and 301-redirects unless the client percent-encodes it.
func TestUserClaims_DeleteNamespacedName(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ccnsadmin", "password123", "ccns@test.com")
	usr := createTestUser(t, "ccnsuser", "password123", "ccnsuser@test.com")

	const name = "https://app.example.com/tier"
	adminUpsertClaim(t, ts, adminToken, usr.ID, name, "gold")

	req, _ := http.NewRequest("DELETE",
		ts.BaseURL+"/admin/api/users/"+usr.ID+"/claims/"+url.PathEscape(name), nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	claims := listUserClaims(t, ts, adminToken, usr.ID)
	assert.Empty(t, claims)
}

func listUserClaims(t *testing.T, ts *TestServer, adminToken, userID string) []userclaim.UserClaimResponse {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.BaseURL+"/admin/api/users/"+userID+"/claims", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var listResp model.ApiResponse[[]userclaim.UserClaimResponse]
	require.NoError(t, json.Unmarshal(body, &listResp))
	return listResp.Data
}

func TestUserClaims_EmittedWithScope(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ccadmin2", "password123", "ccadmin2@test.com")
	usr := createTestUser(t, "ccuser", "password123", "ccuser@test.com")

	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "gold")
	adminUpsertClaim(t, ts, adminToken, usr.ID, "region", "eu")

	tr := passwordToken(t, ts, "ccuser", "password123", "openid custom_claims")

	idClaims := decodeJWTPayload(t, tr.IDToken)
	assert.Equal(t, "gold", idClaims["tier"])
	assert.Equal(t, "eu", idClaims["region"])

	atClaims := decodeJWTPayload(t, tr.AccessToken)
	assert.Equal(t, "gold", atClaims["tier"])

	// UserInfo
	req, _ := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	uiResp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = uiResp.Body.Close() }()
	uiBody, _ := io.ReadAll(uiResp.Body)
	var userinfo map[string]interface{}
	require.NoError(t, json.Unmarshal(uiBody, &userinfo))
	assert.Equal(t, "gold", userinfo["tier"])
}

func TestUserClaims_AbsentWithoutScope(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ccadmin3", "password123", "ccadmin3@test.com")
	usr := createTestUser(t, "ccuser2", "password123", "ccuser2@test.com")

	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "gold")

	tr := passwordToken(t, ts, "ccuser2", "password123", "openid profile")

	idClaims := decodeJWTPayload(t, tr.IDToken)
	assert.Nil(t, idClaims["tier"])
	atClaims := decodeJWTPayload(t, tr.AccessToken)
	assert.Nil(t, atClaims["tier"])
}

func TestUserClaims_ScopeRejectedWhenNotAllowedForClient(t *testing.T) {
	ts := startTestServer(t)
	seedScopedClient(t) // scoped-e2e-client: scopes = "openid profile", no custom_claims
	createTestUser(t, "ccscopeuser", "password123", "ccscope@test.com")

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "scoped-e2e-client")
	form.Set("username", "ccscopeuser")
	form.Set("password", "password123")
	form.Set("scope", "openid custom_claims")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "invalid_scope")
}

func TestUserClaims_RefreshReReadsLive(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ccadmin4", "password123", "ccadmin4@test.com")
	usr := createTestUser(t, "ccuser3", "password123", "ccuser3@test.com")

	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "gold")
	tr := passwordToken(t, ts, "ccuser3", "password123", "openid custom_claims offline_access")
	require.NotEmpty(t, tr.RefreshToken)

	// Change the claim, then refresh
	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "platinum")

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", "test-client")
	form.Set("refresh_token", tr.RefreshToken)
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh failed: %s", string(body))
	var refreshed token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &refreshed))

	atClaims := decodeJWTPayload(t, refreshed.AccessToken)
	assert.Equal(t, "platinum", atClaims["tier"], "refreshed token must reflect the current claim value")
}

func TestUserClaims_DroppedOnRefreshDownscope(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ccadmin5", "password123", "ccadmin5@test.com")
	usr := createTestUser(t, "ccuser4", "password123", "ccuser4@test.com")

	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "gold")
	tr := passwordToken(t, ts, "ccuser4", "password123", "openid custom_claims offline_access")

	// Refresh narrowing the scope to drop custom_claims.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", "test-client")
	form.Set("refresh_token", tr.RefreshToken)
	form.Set("scope", "openid")
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh failed: %s", string(body))
	var refreshed token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &refreshed))

	assert.Nil(t, decodeJWTPayload(t, refreshed.AccessToken)["tier"],
		"custom claims must be gone once custom_claims is dropped on refresh")
	assert.Nil(t, decodeJWTPayload(t, refreshed.IDToken)["tier"])
}

func TestUserClaims_NotInIntrospectionResponse(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ccadmin6", "password123", "ccadmin6@test.com")
	usr := createTestUser(t, "ccuser5", "password123", "ccuser5@test.com")
	adminUpsertClaim(t, ts, adminToken, usr.ID, "tier", "gold")

	// ROPC on the confidential client so it can introspect its own token.
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "ccuser5")
	form.Set("password", "password123")
	form.Set("scope", "openid custom_claims")
	tokReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth("e2e-confidential", "e2e-secret")
	tokResp, err := ts.Client.Do(tokReq)
	require.NoError(t, err)
	defer func() { _ = tokResp.Body.Close() }()
	tb, _ := io.ReadAll(tokResp.Body)
	require.Equal(t, http.StatusOK, tokResp.StatusCode, "token: %s", string(tb))
	var tr token.TokenResponse
	require.NoError(t, json.Unmarshal(tb, &tr))
	require.Equal(t, "gold", decodeJWTPayload(t, tr.AccessToken)["tier"], "sanity: claim is in the token")

	iForm := url.Values{}
	iForm.Set("token", tr.AccessToken)
	iReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/introspect", strings.NewReader(iForm.Encode()))
	iReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	iReq.SetBasicAuth("e2e-confidential", "e2e-secret")
	iResp, err := ts.Client.Do(iReq)
	require.NoError(t, err)
	defer func() { _ = iResp.Body.Close() }()
	ib, _ := io.ReadAll(iResp.Body)
	var introspect map[string]interface{}
	require.NoError(t, json.Unmarshal(ib, &introspect))
	assert.True(t, introspect["active"].(bool), "sanity: token is active: %s", string(ib))
	assert.NotContains(t, introspect, "tier", "introspection must not surface custom claims")
}
