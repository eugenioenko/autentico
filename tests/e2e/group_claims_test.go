package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/groupclaim"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/require"
)

func TestGroupClaimsEndToEnd(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "groupclaimadmin", "password123", "gcadmin@test.com")
	alice := createTestUser(t, "gcalice", "password123", "gcalice@test.com")
	app1 := adminCreateGroup(t, ts, adminToken, "app1", "")
	app2 := adminCreateGroup(t, ts, adminToken, "app2", "")
	outsider := adminCreateGroup(t, ts, adminToken, "outsider", "")
	adminAddMember(t, ts, adminToken, app1.ID, alice.ID)
	adminAddMember(t, ts, adminToken, app2.ID, alice.ID)
	call := func(method, path, bearer, body string, status int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, ts.BaseURL+path, strings.NewReader(body))
		require.NoError(t, err)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, status, resp.StatusCode, "%s %s: %s", method, path, data)
		return data
	}
	base := "/admin/api/groups/" + app1.ID + "/claims"
	for _, g := range []string{app1.ID, app2.ID, outsider.ID} {
		call("POST", "/admin/api/groups/"+g+"/claims", adminToken, `{"name":"role","value":"viewer"}`, 201)
	}
	var listed model.ApiResponse[[]groupclaim.GroupClaimResponse]
	require.NoError(t, json.Unmarshal(call("GET", base, adminToken, "", 200), &listed))
	require.Len(t, listed.Data, 1)
	require.Equal(t, "role", listed.Data[0].Name)
	// Namespaced local names must round-trip through the actual catch-all route.
	call("POST", base, adminToken, `{"name":"https://app.example.com/tier","value":"gold"}`, 201)
	call("DELETE", base+"/"+url.PathEscape("https://app.example.com/tier"), adminToken, "", 200)
	regular := passwordToken(t, ts, "gcalice", "password123", "openid").AccessToken
	for _, method := range []string{"GET", "POST", "DELETE"} {
		path := base
		if method == "DELETE" {
			path += "/role"
		}
		for bearer, status := range map[string]int{"": 401, regular: 403} {
			call(method, path, bearer, `{"name":"role","value":"admin"}`, status)
		}
	}
	assertClaims := func(tr token.TokenResponse, want map[string]string) {
		t.Helper()
		var ui map[string]interface{}
		require.NoError(t, json.Unmarshal(call("GET", "/oauth2/userinfo", tr.AccessToken, "", 200), &ui))
		require.Equal(t, "user", decodeJWTPayload(t, tr.AccessToken)["role"], "group claims cannot change the Autentico role")
		for _, claims := range []map[string]interface{}{decodeJWTPayload(t, tr.AccessToken), decodeJWTPayload(t, tr.IDToken), ui} {
			require.Equal(t, alice.ID, claims["sub"], "group claims cannot change the authenticated subject")
			for _, name := range []string{"app1.role", "app2.role", "renamed.role", "outsider.role"} {
				if value, ok := want[name]; ok {
					require.Equal(t, value, claims[name], name)
				} else {
					require.NotContains(t, claims, name)
				}
			}
			require.NotEqual(t, "viewer", claims["role"])
		}
	}
	assertClaims(passwordToken(t, ts, "gcalice", "password123", "openid groups"), map[string]string{})
	tr := passwordToken(t, ts, "gcalice", "password123", "openid custom_claims offline_access")
	assertClaims(tr, map[string]string{"app1.role": "viewer", "app2.role": "viewer"})
	refresh := func(scope string) {
		t.Helper()
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"test-client"}, "refresh_token": {tr.RefreshToken}}
		if scope != "" {
			form.Set("scope", scope)
		}
		resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, 200, resp.StatusCode, string(data))
		require.NoError(t, json.Unmarshal(data, &tr))
	}
	call("POST", base, adminToken, `{"name":"role","value":"editor"}`, 201)
	// UserInfo reads current assignments, while an already issued JWT remains a snapshot.
	var live map[string]interface{}
	require.NoError(t, json.Unmarshal(call("GET", "/oauth2/userinfo", tr.AccessToken, "", 200), &live))
	require.Equal(t, "editor", live["app1.role"])
	require.Equal(t, "viewer", decodeJWTPayload(t, tr.AccessToken)["app1.role"])
	refresh("")
	assertClaims(tr, map[string]string{"app1.role": "editor", "app2.role": "viewer"})
	adminUpsertClaim(t, ts, adminToken, alice.ID, "app1.role", "owner")
	refresh("")
	assertClaims(tr, map[string]string{"app1.role": "owner", "app2.role": "viewer"})
	call("DELETE", "/admin/api/groups/"+app1.ID+"/members/"+alice.ID, adminToken, "", 200)
	refresh("")
	assertClaims(tr, map[string]string{"app1.role": "owner", "app2.role": "viewer"})
	call("DELETE", "/admin/api/users/"+alice.ID+"/claims/app1.role", adminToken, "", 200)
	refresh("")
	assertClaims(tr, map[string]string{"app2.role": "viewer"})
	call("PUT", "/admin/api/groups/"+app2.ID, adminToken, `{"name":"renamed"}`, 200)
	refresh("")
	assertClaims(tr, map[string]string{"renamed.role": "viewer"})
	call("DELETE", "/admin/api/groups/"+app2.ID+"/claims/role", adminToken, "", 200)
	refresh("")
	assertClaims(tr, map[string]string{})
	call("POST", "/admin/api/groups/"+app2.ID+"/claims", adminToken, `{"name":"role","value":"viewer"}`, 201)
	refresh("openid")
	assertClaims(tr, map[string]string{})
}

func TestGroupClaimsStorageFailureDoesNotIssuePartialCredentials(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "gcfailureadmin", "password123", "gcfailureadmin@test.com")
	alice := createTestUser(t, "gcfailurealice", "password123", "gcfailurealice@test.com")
	g := adminCreateGroup(t, ts, adminToken, "app1", "")
	adminAddMember(t, ts, adminToken, g.ID, alice.ID)
	require.NoError(t, groupclaim.UpsertClaim(g.ID, "role", "editor"))
	tr := passwordToken(t, ts, "gcfailurealice", "password123", "openid custom_claims offline_access")
	var tokensBefore, sessionsBefore int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&tokensBefore))
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessionsBefore))
	_, err := db.GetDB().Exec(`ALTER TABLE group_claims RENAME TO unavailable_group_claims`)
	require.NoError(t, err)
	checkFailure := func(req *http.Request) {
		t.Helper()
		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode, string(body))
		require.Empty(t, resp.Header.Values("Set-Cookie"))
		var payload map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &payload))
		for _, name := range []string{"access_token", "id_token", "refresh_token", "sub", "app1.role"} {
			require.NotContains(t, payload, name, "a failed claim lookup must not return partial credentials or UserInfo")
		}
	}
	passwordForm := url.Values{
		"grant_type": {"password"}, "client_id": {"test-client"},
		"username": {"gcfailurealice"}, "password": {"password123"}, "scope": {"openid custom_claims"},
	}
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(passwordForm.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	checkFailure(req)
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {"test-client"}, "refresh_token": {tr.RefreshToken}}
	req, err = http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(refreshForm.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	checkFailure(req)
	req, err = http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	checkFailure(req)
	var tokensAfter, sessionsAfter int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&tokensAfter))
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessionsAfter))
	require.Equal(t, tokensBefore, tokensAfter)
	require.Equal(t, sessionsBefore, sessionsAfter)
	// Scope gating keeps unrelated token issuance independent of this storage.
	passwordToken(t, ts, "gcfailurealice", "password123", "openid")
	_, err = db.GetDB().Exec(`ALTER TABLE unavailable_group_claims RENAME TO group_claims`)
	require.NoError(t, err)
	// A failed resolution did not consume the refresh grant; it succeeds after recovery.
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", refreshForm)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var refreshed token.TokenResponse
	require.NoError(t, json.Unmarshal(body, &refreshed))
	require.Equal(t, "editor", decodeJWTPayload(t, refreshed.AccessToken)["app1.role"])
	require.Equal(t, "editor", decodeJWTPayload(t, refreshed.IDToken)["app1.role"])
}
