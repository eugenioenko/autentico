package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func seedAccessFixtures(t *testing.T) {
	t.Helper()
	testutils.WithTestDB(t)
	for _, stmt := range []string{
		`INSERT INTO users (id, username, email, password) VALUES ('u-direct', 'direct', 'direct@test.local', 'x')`,
		`INSERT INTO users (id, username, email, password) VALUES ('u-member', 'member', 'member@test.local', 'x')`,
		`INSERT INTO users (id, username, email, password) VALUES ('u-other', 'other', 'other@test.local', 'x')`,
		`INSERT INTO users (id, username, email, password) VALUES ('u-second', 'second', 'second@test.local', 'x')`,
		`INSERT INTO groups (id, name) VALUES ('g-staff', 'staff')`,
		`INSERT INTO groups (id, name) VALUES ('g-ops', 'ops')`,
		`INSERT INTO groups (id, name) VALUES ('g-unbound', 'unbound')`,
		`INSERT INTO user_groups (user_id, group_id) VALUES ('u-member', 'g-staff')`,
		`INSERT INTO user_groups (user_id, group_id) VALUES ('u-second', 'g-ops')`,
		`INSERT INTO user_groups (user_id, group_id) VALUES ('u-other', 'g-unbound')`,
	} {
		_, err := db.GetDB().Exec(stmt)
		require.NoError(t, err, stmt)
	}
}

func createAccessClient(t *testing.T, id string, req ClientCreateRequest) *ClientResponse {
	t.Helper()
	req.ClientName = "Access " + id
	req.RedirectURIs = []string{"https://app.example/callback"}
	resp, err := CreateClientWithID(id, req)
	require.NoError(t, err)
	return resp
}

func loadClient(t *testing.T, id string) *Client {
	t.Helper()
	c, err := ClientByClientIDIncludingDisabled(id)
	require.NoError(t, err)
	return c
}

func requireAllowed(t *testing.T, c *Client, userID string) {
	t.Helper()
	require.NoError(t, CheckUserAccess(c, userID))
}

func requireDenied(t *testing.T, c *Client, userID string) {
	t.Helper()
	require.ErrorIs(t, CheckUserAccess(c, userID), ErrAccessDenied)
}

func TestCheckUserAccess_UnrestrictedAllowsEveryone(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "open", ClientCreateRequest{AllowedGroups: []string{"g-staff"}})
	c := loadClient(t, "open")
	require.False(t, c.RestrictAccess)
	for _, id := range []string{"u-direct", "u-member", "u-other", "missing-user"} {
		requireAllowed(t, c, id)
	}
}

func TestCheckUserAccess_RestrictedEmptyListsDenyEveryone(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "locked", ClientCreateRequest{RestrictAccess: true})
	c := loadClient(t, "locked")
	require.True(t, c.RestrictAccess)
	for _, id := range []string{"u-direct", "u-member", "u-other"} {
		requireDenied(t, c, id)
	}
}

func TestCheckUserAccess_AllowedUserOrAnyAllowedGroup(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{
		RestrictAccess: true,
		AllowedUsers:   []string{"u-direct"},
		AllowedGroups:  []string{"g-staff", "g-ops"},
	})
	c := loadClient(t, "app")
	requireAllowed(t, c, "u-direct")
	requireAllowed(t, c, "u-member")
	requireAllowed(t, c, "u-second")
	requireDenied(t, c, "u-other")
	requireDenied(t, c, "missing-user")
}

func TestCheckUserAccess_ListsOnOneClientDoNotAffectAnother(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "a", ClientCreateRequest{RestrictAccess: true, AllowedUsers: []string{"u-direct"}})
	createAccessClient(t, "b", ClientCreateRequest{RestrictAccess: true, AllowedUsers: []string{"u-other"}})
	requireAllowed(t, loadClient(t, "a"), "u-direct")
	requireDenied(t, loadClient(t, "a"), "u-other")
	requireAllowed(t, loadClient(t, "b"), "u-other")
	requireDenied(t, loadClient(t, "b"), "u-direct")
}

func TestCheckUserAccess_MembershipChangesApplyImmediately(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{RestrictAccess: true, AllowedGroups: []string{"g-staff"}})
	c := loadClient(t, "app")
	requireDenied(t, c, "u-other")
	_, err := db.GetDB().Exec(`INSERT INTO user_groups (user_id, group_id) VALUES ('u-other', 'g-staff')`)
	require.NoError(t, err)
	requireAllowed(t, c, "u-other")
	_, err = db.GetDB().Exec(`DELETE FROM user_groups WHERE user_id = 'u-member'`)
	require.NoError(t, err)
	requireDenied(t, c, "u-member")
}

func TestCheckUserAccess_DeletingLastGroupOrUserFailsClosed(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{RestrictAccess: true, AllowedGroups: []string{"g-staff"}, AllowedUsers: []string{"u-direct"}})
	_, err := db.GetDB().Exec(`DELETE FROM groups WHERE id = 'g-staff'`)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`DELETE FROM users WHERE id = 'u-direct'`)
	require.NoError(t, err)

	c := loadClient(t, "app")
	require.True(t, c.RestrictAccess)
	lists, err := AccessListsByClientIDs([]string{"app"})
	require.NoError(t, err)
	require.Empty(t, lists["app"].Groups)
	require.Empty(t, lists["app"].Users)
	requireDenied(t, c, "u-member")
	requireDenied(t, c, "u-other")
}

func TestCheckUserAccess_BuiltInClientsCanBeRestricted(t *testing.T) {
	seedAccessFixtures(t)
	for _, id := range []string{config.AdminClientID, config.AccountClientID} {
		createAccessClient(t, id, ClientCreateRequest{RestrictAccess: true, AllowedUsers: []string{"u-direct"}})
		c := loadClient(t, id)
		requireAllowed(t, c, "u-direct")
		requireDenied(t, c, "u-other")
	}
}

func TestCheckUserAccess_NilClientAllows(t *testing.T) {
	seedAccessFixtures(t)
	require.NoError(t, CheckUserAccess(nil, "u-other"))
}

func TestCheckUserAccessByClientID_MissingOrInactiveClientFailsClosed(t *testing.T) {
	seedAccessFixtures(t)
	require.ErrorIs(t, CheckUserAccessByClientID("missing", "u-direct"), ErrAccessDenied)

	createAccessClient(t, "app", ClientCreateRequest{})
	require.NoError(t, CheckUserAccessByClientID("app", "u-direct"))
	require.NoError(t, DeleteClient("app"))
	require.ErrorIs(t, CheckUserAccessByClientID("app", "u-direct"), ErrAccessDenied)
}

func TestCheckUserAccessByClientID_LookupFailureIsNotAccessDenied(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{})
	_, err := db.GetDB().Exec(`ALTER TABLE clients RENAME COLUMN restrict_access TO restrict_access_gone`)
	require.NoError(t, err)
	err = CheckUserAccessByClientID("app", "u-direct")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrAccessDenied)
}

func TestCheckUserAccess_DatabaseFailureIsNotAccessDenied(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{RestrictAccess: true})
	c := loadClient(t, "app")
	_, err := db.GetDB().Exec(`DROP TABLE client_allowed_users`)
	require.NoError(t, err)
	err = CheckUserAccess(c, "u-direct")
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrAccessDenied))
}

func TestCreateClient_AccessListsAreDeduplicatedAndReturned(t *testing.T) {
	seedAccessFixtures(t)
	resp := createAccessClient(t, "app", ClientCreateRequest{
		RestrictAccess: true,
		AllowedGroups:  []string{"g-staff", "g-ops", "g-staff"},
		AllowedUsers:   []string{"u-direct", "u-direct"},
	})
	require.True(t, resp.RestrictAccess)
	require.Equal(t, []string{"g-ops", "g-staff"}, resp.AllowedGroups)
	require.Equal(t, []string{"u-direct"}, resp.AllowedUsers)
}

func TestCreateClient_UnknownAccessEntryRollsBackClient(t *testing.T) {
	seedAccessFixtures(t)
	for _, req := range []ClientCreateRequest{
		{RestrictAccess: true, AllowedGroups: []string{"g-staff", "g-missing"}},
		{RestrictAccess: true, AllowedUsers: []string{"u-missing"}},
	} {
		req.ClientName = "Broken"
		req.RedirectURIs = []string{"https://app.example/callback"}
		_, err := CreateClientWithID("broken", req)
		require.ErrorIs(t, err, ErrInvalidAccess)
		_, err = ClientByClientIDIncludingDisabled("broken")
		require.Error(t, err, "a failed access write must not leave the client behind")
	}
}

func TestCreateClientWithIDTx_WritesUnrestrictedDefault(t *testing.T) {
	seedAccessFixtures(t)
	tx, err := db.GetDB().Begin()
	require.NoError(t, err)
	_, err = CreateClientWithIDTx(tx, "tx-app", ClientCreateRequest{ClientName: "Tx", RedirectURIs: []string{"https://app.example/callback"}})
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	require.False(t, loadClient(t, "tx-app").RestrictAccess)
}

func TestUpdateClient_AccessFields(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{})

	groups := []string{"g-staff"}
	users := []string{"u-direct"}
	require.NoError(t, UpdateClient("app", ClientUpdateRequest{RestrictAccess: boolPtr(true), AllowedGroups: &groups, AllowedUsers: &users}))
	c := loadClient(t, "app")
	require.True(t, c.RestrictAccess)
	requireAllowed(t, c, "u-direct")
	requireAllowed(t, c, "u-member")
	requireDenied(t, c, "u-second")

	// Omitted fields keep their stored values.
	require.NoError(t, UpdateClient("app", ClientUpdateRequest{ClientName: "Renamed"}))
	c = loadClient(t, "app")
	require.True(t, c.RestrictAccess)
	lists, err := AccessListsByClientIDs([]string{"app"})
	require.NoError(t, err)
	require.Equal(t, []string{"g-staff"}, lists["app"].Groups)
	require.Equal(t, []string{"u-direct"}, lists["app"].Users)

	// A provided list replaces the stored one.
	replaced := []string{"g-ops"}
	require.NoError(t, UpdateClient("app", ClientUpdateRequest{AllowedGroups: &replaced}))
	c = loadClient(t, "app")
	requireDenied(t, c, "u-member")
	requireAllowed(t, c, "u-second")
	requireAllowed(t, c, "u-direct")

	// Empty lists clear entries; restriction alone then admits nobody.
	empty := []string{}
	require.NoError(t, UpdateClient("app", ClientUpdateRequest{AllowedGroups: &empty, AllowedUsers: &empty}))
	c = loadClient(t, "app")
	requireDenied(t, c, "u-direct")
	requireDenied(t, c, "u-second")

	// Turning restriction off admits everyone again.
	require.NoError(t, UpdateClient("app", ClientUpdateRequest{RestrictAccess: boolPtr(false)}))
	requireAllowed(t, loadClient(t, "app"), "u-other")
}

func TestUpdateClient_UnknownAccessEntryChangesNothing(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{RestrictAccess: true, AllowedGroups: []string{"g-staff"}})
	groups := []string{"g-ops", "g-missing"}
	err := UpdateClient("app", ClientUpdateRequest{ClientName: "Changed", RestrictAccess: boolPtr(false), AllowedGroups: &groups})
	require.ErrorIs(t, err, ErrInvalidAccess)

	c := loadClient(t, "app")
	require.Equal(t, "Access app", c.ClientName)
	require.True(t, c.RestrictAccess)
	lists, err := AccessListsByClientIDs([]string{"app"})
	require.NoError(t, err)
	require.Equal(t, []string{"g-staff"}, lists["app"].Groups)
}

func TestUpdateClient_BuiltInClientRestriction(t *testing.T) {
	seedAccessFixtures(t)
	for _, id := range []string{config.AdminClientID, config.AccountClientID} {
		createAccessClient(t, id, ClientCreateRequest{})
		groups := []string{"g-staff"}
		require.NoError(t, UpdateClient(id, ClientUpdateRequest{RestrictAccess: boolPtr(true), AllowedGroups: &groups}))
		c := loadClient(t, id)
		requireAllowed(t, c, "u-member")
		requireDenied(t, c, "u-other")
		require.NoError(t, UpdateClient(id, ClientUpdateRequest{RestrictAccess: boolPtr(false)}))
		requireAllowed(t, loadClient(t, id), "u-other")
	}
}

func TestUpdateClient_TooManyEntriesRejected(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{})
	many := make([]string, maxAccessEntries+1)
	for i := range many {
		many[i] = "u-direct"
	}
	require.ErrorIs(t, UpdateClient("app", ClientUpdateRequest{AllowedUsers: &many}), ErrInvalidAccess)
}

func TestAccessDeniedRedirect(t *testing.T) {
	target, err := AccessDeniedRedirect("https://app.example/callback?tenant=a", "xyz")
	require.NoError(t, err)
	u, err := url.Parse(target)
	require.NoError(t, err)
	require.Equal(t, "app.example", u.Host)
	require.Equal(t, "/callback", u.Path)
	q := u.Query()
	require.Equal(t, "a", q.Get("tenant"))
	require.Equal(t, "access_denied", q.Get("error"))
	require.Equal(t, "xyz", q.Get("state"))
	require.NotEmpty(t, q.Get("error_description"))
	require.Empty(t, q.Get("code"))

	target, err = AccessDeniedRedirect("https://app.example/callback", "")
	require.NoError(t, err)
	u, _ = url.Parse(target)
	require.False(t, u.Query().Has("state"))
}

func TestLogAccessDenied_RecordsNoListDetails(t *testing.T) {
	seedAccessFixtures(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = "-1" })
	LogAccessDenied("u-other", "other", "app", "password", "203.0.113.9")
	var target, detail string
	var actor *string
	err := db.GetDB().QueryRow(`SELECT target_id, detail, actor_id FROM audit_logs WHERE event = 'client_access_denied'`).Scan(&target, &detail, &actor)
	require.NoError(t, err)
	require.Equal(t, "app", target)
	require.NotNil(t, actor)
	require.Equal(t, "u-other", *actor)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal([]byte(detail), &parsed))
	require.Equal(t, map[string]string{"user_id": "u-other", "flow": "password"}, parsed)
}

func doClientJSON(t *testing.T, method, path, clientID string, body any, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if clientID != "" {
		req.SetPathValue("client_id", clientID)
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func TestHandlers_AccessFieldsRoundTrip(t *testing.T) {
	seedAccessFixtures(t)

	rr := doClientJSON(t, http.MethodPost, "/admin/api/clients", "", map[string]any{
		"client_id": "app", "client_name": "App", "redirect_uris": []string{"https://app.example/callback"},
		"restrict_access": true, "allowed_groups": []string{"g-staff"}, "allowed_users": []string{"u-direct"},
	}, HandleRegister)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var created ClientResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	require.True(t, created.RestrictAccess)
	require.Equal(t, []string{"g-staff"}, created.AllowedGroups)
	require.Equal(t, []string{"u-direct"}, created.AllowedUsers)

	rr = doClientJSON(t, http.MethodGet, "/admin/api/clients/app", "app", nil, HandleGetClient)
	require.Equal(t, http.StatusOK, rr.Code)
	var info ClientInfoResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &info))
	require.True(t, info.RestrictAccess)
	require.Equal(t, []string{"g-staff"}, info.AllowedGroups)
	require.Equal(t, []string{"u-direct"}, info.AllowedUsers)

	rr = doClientJSON(t, http.MethodPut, "/admin/api/clients/app", "app", map[string]any{
		"allowed_groups": []string{"g-ops"}, "allowed_users": []string{},
	}, HandleUpdateClient)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &info))
	require.True(t, info.RestrictAccess)
	require.Equal(t, []string{"g-ops"}, info.AllowedGroups)
	require.Equal(t, []string{}, info.AllowedUsers)

	rr = doClientJSON(t, http.MethodGet, "/admin/api/clients", "", nil, HandleAdminListClients)
	require.Equal(t, http.StatusOK, rr.Code)
	var list struct {
		Data struct {
			Items []ClientInfoResponse `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list.Data.Items, 1)
	require.Equal(t, []string{"g-ops"}, list.Data.Items[0].AllowedGroups)
	require.Equal(t, []string{}, list.Data.Items[0].AllowedUsers)
}

func TestHandlers_UnrestrictedClientReportsEmptyLists(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{})
	rr := doClientJSON(t, http.MethodGet, "/admin/api/clients/app", "app", nil, HandleGetClient)
	require.Equal(t, http.StatusOK, rr.Code)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &raw))
	require.Equal(t, false, raw["restrict_access"])
	require.Equal(t, []any{}, raw["allowed_groups"])
	require.Equal(t, []any{}, raw["allowed_users"])
}

func TestHandlers_InvalidAccessMetadata(t *testing.T) {
	seedAccessFixtures(t)
	createAccessClient(t, "app", ClientCreateRequest{})

	cases := []struct {
		name     string
		method   string
		clientID string
		body     map[string]any
		handler  http.HandlerFunc
	}{
		{"create unknown group", http.MethodPost, "", map[string]any{"client_id": "new", "client_name": "New", "redirect_uris": []string{"https://app.example/cb"}, "allowed_groups": []string{"g-missing"}}, HandleRegister},
		{"create unknown user", http.MethodPost, "", map[string]any{"client_id": "new", "client_name": "New", "redirect_uris": []string{"https://app.example/cb"}, "allowed_users": []string{"u-missing"}}, HandleRegister},
		{"update unknown group", http.MethodPut, "app", map[string]any{"allowed_groups": []string{"g-missing"}}, HandleUpdateClient},
		{"update unknown user", http.MethodPut, "app", map[string]any{"allowed_users": []string{"u-missing"}}, HandleUpdateClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := doClientJSON(t, tc.method, "/admin/api/clients", tc.clientID, tc.body, tc.handler)
			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			require.Equal(t, "invalid_client_metadata", body["error"])
		})
	}
	_, err := ClientByClientIDIncludingDisabled("new")
	require.Error(t, err)
}
