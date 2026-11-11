package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

const accessRedirectURI = "http://localhost:3000/callback"

type accessFixture struct {
	ts         *TestServer
	adminToken string
	staffID    string
	allowedID  string
	memberID   string
	outsiderID string
}

func setupAccessFixture(t *testing.T) accessFixture {
	t.Helper()
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "accessadmin", "password123", "accessadmin@test.com")
	allowed := createTestUser(t, "acc-direct", "password123", "acc-direct@test.com")
	member := createTestUser(t, "acc-member", "password123", "acc-member@test.com")
	outsider := createTestUser(t, "acc-outsider", "password123", "acc-outsider@test.com")
	staff := adminCreateGroup(t, ts, adminToken, "acc-staff", "")
	adminAddMember(t, ts, adminToken, staff.ID, member.ID)
	return accessFixture{ts: ts, adminToken: adminToken, staffID: staff.ID, allowedID: allowed.ID, memberID: member.ID, outsiderID: outsider.ID}
}

func (f accessFixture) adminJSON(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, f.ts.BaseURL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.adminToken)
	resp, err := f.ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, data
}

func (f accessFixture) createRestrictedClient(t *testing.T, clientID string, extra map[string]any) {
	t.Helper()
	body := map[string]any{
		"client_id":                  clientID,
		"client_name":                "Restricted " + clientID,
		"redirect_uris":              []string{accessRedirectURI},
		"grant_types":                []string{"authorization_code", "password", "refresh_token"},
		"scopes":                     "openid profile email offline_access",
		"client_type":                "public",
		"token_endpoint_auth_method": "none",
		"restrict_access":            true,
		"allowed_groups":             []string{f.staffID},
		"allowed_users":              []string{f.allowedID},
	}
	for k, v := range extra {
		body[k] = v
	}
	status, data := f.adminJSON(t, http.MethodPost, "/admin/api/clients", body)
	require.Equal(t, http.StatusCreated, status, string(data))
}

func (f accessFixture) updateClient(t *testing.T, clientID string, body map[string]any) {
	t.Helper()
	status, data := f.adminJSON(t, http.MethodPut, "/admin/api/clients/"+clientID, body)
	require.Equal(t, http.StatusOK, status, string(data))
}

func passwordGrant(t *testing.T, ts *TestServer, clientID, username string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"}, "client_id": {clientID}, "username": {username},
		"password": {"password123"}, "scope": {"openid offline_access"},
	}
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

func postToken(t *testing.T, ts *TestServer, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

// browserLogin submits the login form with a fresh browser and returns the final redirect.
func browserLogin(t *testing.T, ts *TestServer, client *http.Client, clientID, username, state string) (*url.URL, *http.Response) {
	t.Helper()
	params := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {accessRedirectURI},
		"scope": {"openid profile email"}, "state": {state},
		"code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
	}
	resp, err := client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, string(page))
	html := string(page)

	form := url.Values{
		"username": {username}, "password": {"password123"}, "redirect_uri": {accessRedirectURI},
		"scope": {"openid profile email"}, "state": {state}, "client_id": {clientID},
		"code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
		"gorilla.csrf.Token": {getCSRFToken(html)}, "authorize_sig": {getAuthorizeSig(html)},
		"prompt": {getHiddenField(html, "prompt")}, "max_age": {getHiddenField(html, "max_age")},
	}
	req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")
	loginResp, err := client.Do(req)
	require.NoError(t, err)
	_ = loginResp.Body.Close()
	require.Equal(t, http.StatusFound, loginResp.StatusCode)
	location, err := url.Parse(loginResp.Header.Get("Location"))
	require.NoError(t, err)
	return location, loginResp
}

func authorizeWithSession(t *testing.T, ts *TestServer, client *http.Client, clientID, state, prompt string) *http.Response {
	t.Helper()
	params := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {accessRedirectURI},
		"scope": {"openid profile email"}, "state": {state},
		"code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
	}
	if prompt != "" {
		params.Set("prompt", prompt)
	}
	resp, err := client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp
}

func requireAccessDeniedRedirect(t *testing.T, location *url.URL, state string) {
	t.Helper()
	require.Equal(t, "localhost:3000", location.Host)
	require.Equal(t, "/callback", location.Path)
	q := location.Query()
	require.Equal(t, "access_denied", q.Get("error"))
	require.Equal(t, state, q.Get("state"))
	require.Empty(t, q.Get("code"))
}

func countAccessDenied(t *testing.T, clientID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE event = 'client_access_denied' AND target_id = ?`, clientID).Scan(&n))
	return n
}

func TestClientAccess_BrowserLogin(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-web", nil)

	for _, username := range []string{"acc-direct", "acc-member"} {
		location, _ := browserLogin(t, f.ts, newClientWithJar(), "restricted-web", username, "s-"+username)
		require.Empty(t, location.Query().Get("error"), username)
		code := location.Query().Get("code")
		require.NotEmpty(t, code, username)
		status, body := postToken(t, f.ts, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {accessRedirectURI},
			"client_id": {"restricted-web"}, "code_verifier": {testCodeVerifier},
		})
		require.Equal(t, http.StatusOK, status, body)
		require.NotEmpty(t, body["access_token"])
	}

	location, resp := browserLogin(t, f.ts, newClientWithJar(), "restricted-web", "acc-outsider", "s-out")
	requireAccessDeniedRedirect(t, location, "s-out")
	for _, c := range resp.Cookies() {
		require.NotContains(t, c.Name, config.GetBootstrap().AuthIdpSessionCookieName, "a refused login must not create a browser session")
	}
}

func TestClientAccess_UnrestrictedAndBuiltInClientsAdmitEveryone(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-web", nil)

	location, _ := browserLogin(t, f.ts, newClientWithJar(), "test-client", "acc-outsider", "s-open")
	require.NotEmpty(t, location.Query().Get("code"))
	status, body := passwordGrant(t, f.ts, "autentico-admin", "acc-outsider")
	require.Equal(t, http.StatusOK, status, body)

	status, data := f.adminJSON(t, http.MethodPut, "/admin/api/clients/autentico-admin", map[string]any{"restrict_access": true})
	require.Equal(t, http.StatusBadRequest, status, string(data))
	require.Contains(t, string(data), "invalid_client_metadata")
	status, data = f.adminJSON(t, http.MethodPut, "/admin/api/clients/autentico-account", map[string]any{"allowed_groups": []string{f.staffID}})
	require.Equal(t, http.StatusBadRequest, status, string(data))
}

func TestClientAccess_SSODoesNotBypassRestriction(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-web", nil)

	browser := newClientWithJar()
	location, _ := browserLogin(t, f.ts, browser, "test-client", "acc-outsider", "s-open")
	require.NotEmpty(t, location.Query().Get("code"), "outsider can sign in to the open client")

	for _, prompt := range []string{"", "none"} {
		resp := authorizeWithSession(t, f.ts, browser, "restricted-web", "s-sso", prompt)
		require.Equal(t, http.StatusFound, resp.StatusCode, "prompt=%q", prompt)
		target, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		requireAccessDeniedRedirect(t, target, "s-sso")
	}

	resp := authorizeWithSession(t, f.ts, browser, "test-client", "s-again", "none")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	target, _ := url.Parse(resp.Header.Get("Location"))
	require.NotEmpty(t, target.Query().Get("code"), "the refused client must not end the user's SSO session")

	adminAddMember(t, f.ts, f.adminToken, f.staffID, f.outsiderID)
	resp = authorizeWithSession(t, f.ts, browser, "restricted-web", "s-joined", "none")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	target, _ = url.Parse(resp.Header.Get("Location"))
	require.NotEmpty(t, target.Query().Get("code"), "adding the user to an allowed group grants access via SSO")
}

func TestClientAccess_ConsentRefusesRestrictedUser(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-consent", map[string]any{"consent_required": true})

	browser := newClientWithJar()
	location, _ := browserLogin(t, f.ts, browser, "restricted-consent", "acc-direct", "s-consent")
	require.Equal(t, "/oauth2/consent", location.Path, "allowed user reaches the consent screen")

	f.updateClient(t, "restricted-consent", map[string]any{"allowed_users": []string{}})
	resp, err := browser.Get(f.ts.BaseURL + location.String())
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	target, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	requireAccessDeniedRedirect(t, target, "s-consent")
}

func TestClientAccess_PasswordGrant(t *testing.T) {
	f := setupAccessFixture(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = "-1" })
	f.createRestrictedClient(t, "restricted-api", nil)

	for _, username := range []string{"acc-direct", "acc-member"} {
		status, body := passwordGrant(t, f.ts, "restricted-api", username)
		require.Equal(t, http.StatusOK, status, body)
	}
	before := countAccessDenied(t, "restricted-api")
	status, body := passwordGrant(t, f.ts, "restricted-api", "acc-outsider")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", body["error"])
	require.Nil(t, body["access_token"])
	require.NotContains(t, body["error_description"], "acc-staff", "the response must not reveal group names")
	require.Equal(t, before+1, countAccessDenied(t, "restricted-api"))
	var detail string
	require.NoError(t, db.GetDB().QueryRow(`SELECT detail FROM audit_logs WHERE event = 'client_access_denied' AND target_id = 'restricted-api'`).Scan(&detail))
	require.JSONEq(t, `{"user_id":"`+f.outsiderID+`","flow":"password"}`, detail)
}

func TestClientAccess_WrongPasswordStaysGeneric(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-api", nil)
	form := url.Values{"grant_type": {"password"}, "client_id": {"restricted-api"}, "username": {"acc-outsider"}, "password": {"wrong"}}
	status, body := postToken(t, f.ts, form)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "Invalid username or password", body["error_description"], "access is only evaluated after authentication")
}

func TestClientAccess_RefreshRevalidatesMembership(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-api", nil)

	status, body := passwordGrant(t, f.ts, "restricted-api", "acc-member")
	require.Equal(t, http.StatusOK, status, body)
	refresh := body["refresh_token"].(string)

	status, body = postToken(t, f.ts, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"restricted-api"}})
	require.Equal(t, http.StatusOK, status, body)
	refresh = body["refresh_token"].(string)

	req, err := http.NewRequest(http.MethodDelete, f.ts.BaseURL+"/admin/api/groups/"+f.staffID+"/members/"+f.memberID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+f.adminToken)
	resp, err := f.ts.Client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	status, body = postToken(t, f.ts, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"restricted-api"}})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", body["error"])
	require.Nil(t, body["access_token"])
}

func TestClientAccess_RestrictionEnabledAfterCodeIssued(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-web", map[string]any{"restrict_access": false})

	location, _ := browserLogin(t, f.ts, newClientWithJar(), "restricted-web", "acc-outsider", "s-late")
	code := location.Query().Get("code")
	require.NotEmpty(t, code)

	f.updateClient(t, "restricted-web", map[string]any{"restrict_access": true})
	status, body := postToken(t, f.ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {accessRedirectURI},
		"client_id": {"restricted-web"}, "code_verifier": {testCodeVerifier},
	})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", body["error"])
	require.Nil(t, body["access_token"])
}

func TestClientAccess_DeletedGroupFailsClosed(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-api", map[string]any{"allowed_users": []string{}})

	status, body := passwordGrant(t, f.ts, "restricted-api", "acc-member")
	require.Equal(t, http.StatusOK, status, body)

	status, data := f.adminJSON(t, http.MethodDelete, "/admin/api/groups/"+f.staffID, nil)
	require.Equal(t, http.StatusOK, status, string(data))

	status, data = f.adminJSON(t, http.MethodGet, "/admin/api/clients/restricted-api", nil)
	require.Equal(t, http.StatusOK, status)
	var info map[string]any
	require.NoError(t, json.Unmarshal(data, &info))
	require.Equal(t, true, info["restrict_access"])
	require.Equal(t, []any{}, info["allowed_groups"])

	for _, username := range []string{"acc-member", "acc-outsider", "acc-direct"} {
		status, body = passwordGrant(t, f.ts, "restricted-api", username)
		require.Equal(t, http.StatusBadRequest, status, username)
		require.Equal(t, "invalid_grant", body["error"], username)
	}
}

func TestClientAccess_ClientCredentialsUnaffected(t *testing.T) {
	f := setupAccessFixture(t)
	status, data := f.adminJSON(t, http.MethodPost, "/admin/api/clients", map[string]any{
		"client_id": "restricted-service", "client_name": "Service", "client_secret": "service-secret",
		"redirect_uris": []string{accessRedirectURI}, "grant_types": []string{"client_credentials"},
		"scopes": "read", "client_type": "confidential", "token_endpoint_auth_method": "client_secret_post",
		"restrict_access": true,
	})
	require.Equal(t, http.StatusCreated, status, string(data))
	status, body := postToken(t, f.ts, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"restricted-service"}, "client_secret": {"service-secret"}, "scope": {"read"},
	})
	require.Equal(t, http.StatusOK, status, body)
	require.NotEmpty(t, body["access_token"])
}

func TestClientAccess_AdminAPIValidation(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "restricted-web", nil)

	status, data := f.adminJSON(t, http.MethodGet, "/admin/api/clients/restricted-web", nil)
	require.Equal(t, http.StatusOK, status)
	var info map[string]any
	require.NoError(t, json.Unmarshal(data, &info))
	require.Equal(t, true, info["restrict_access"])
	require.Equal(t, []any{f.staffID}, info["allowed_groups"])
	require.Equal(t, []any{f.allowedID}, info["allowed_users"])

	for _, body := range []map[string]any{
		{"allowed_groups": []string{"missing-group"}},
		{"allowed_users": []string{"missing-user"}},
	} {
		status, data = f.adminJSON(t, http.MethodPut, "/admin/api/clients/restricted-web", body)
		require.Equal(t, http.StatusBadRequest, status, string(data))
		require.Contains(t, string(data), "invalid_client_metadata")
	}

	status, data = f.adminJSON(t, http.MethodGet, "/admin/api/clients/restricted-web", nil)
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, json.Unmarshal(data, &info))
	require.Equal(t, []any{f.staffID}, info["allowed_groups"], "a rejected update leaves the lists unchanged")
	require.Equal(t, []any{f.allowedID}, info["allowed_users"])
}
