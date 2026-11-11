package account

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/devicecode"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func createAccountApp(t *testing.T, id string, restrict bool, groups, users []string) {
	t.Helper()
	_, err := client.CreateClientWithID(id, client.ClientCreateRequest{
		ClientName: id, RedirectURIs: []string{"https://" + id + ".example.com/callback"}, ShowInAccount: true,
		GrantTypes:     []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		RestrictAccess: restrict, AllowedGroups: groups, AllowedUsers: users,
	})
	require.NoError(t, err)
}

func listedApps(t *testing.T, rr []byte) []string {
	t.Helper()
	var response struct {
		Data []AppResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr, &response))
	ids := []string{}
	for _, app := range response.Data {
		ids = append(ids, app.ClientID)
	}
	return ids
}

func TestHandleListApps_HidesRestrictedAppsTheUserCannotUse(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)
	userID := usr.ID
	testutils.InsertTestGroup(t, "g-team", "team")
	testutils.InsertTestGroupMembership(t, userID, "g-team")

	createAccountApp(t, "open", false, nil, nil)
	createAccountApp(t, "by-group", true, []string{"g-team"}, nil)
	createAccountApp(t, "by-user", true, nil, []string{userID})
	createAccountApp(t, "locked", true, nil, nil)

	rr := mockAuthRequest(t, "", http.MethodGet, "/account/api/apps", HandleListApps, info)
	require.Equal(t, http.StatusOK, rr.Code)
	require.ElementsMatch(t, []string{"open", "by-group", "by-user"}, listedApps(t, rr.Body.Bytes()))
}

func TestHandleDeviceAuthorize_RefusedUserLeavesCodePending(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)
	createAccountApp(t, "tv", true, nil, nil)
	require.NoError(t, devicecode.CreateDeviceCode(devicecode.DeviceCode{Code: "device", UserCode: "ABCDEFGH", ClientID: "tv", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))

	rr := mockAuthRequest(t, `{"user_code":"ABCDEFGH"}`, http.MethodPost, "/account/api/device/authorize", HandleDeviceAuthorize, info)
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.Contains(t, rr.Body.String(), `"error":"access_denied"`)
	stored, err := devicecode.DeviceCodeByCode("device")
	require.NoError(t, err)
	require.Equal(t, "pending", stored.Status)
	require.Nil(t, stored.UserID)
}

func TestHandleDeviceAuthorize_AllowedUserApproves(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)
	createAccountApp(t, "tv", true, nil, []string{usr.ID})
	require.NoError(t, devicecode.CreateDeviceCode(devicecode.DeviceCode{Code: "device", UserCode: "ABCDEFGH", ClientID: "tv", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))

	rr := mockAuthRequest(t, `{"user_code":"ABCDEFGH"}`, http.MethodPost, "/account/api/device/authorize", HandleDeviceAuthorize, info)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	stored, err := devicecode.DeviceCodeByCode("device")
	require.NoError(t, err)
	require.Equal(t, "authorized", stored.Status)
}

func TestHandleDeviceAuthorize_AccessCheckFailureIsServerError(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)
	createAccountApp(t, "tv", true, nil, nil)
	require.NoError(t, devicecode.CreateDeviceCode(devicecode.DeviceCode{Code: "device", UserCode: "ABCDEFGH", ClientID: "tv", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))
	_, err := db.GetDB().Exec(`DROP TABLE client_allowed_users`)
	require.NoError(t, err)

	rr := mockAuthRequest(t, `{"user_code":"ABCDEFGH"}`, http.MethodPost, "/account/api/device/authorize", HandleDeviceAuthorize, info)
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	stored, err := devicecode.DeviceCodeByCode("device")
	require.NoError(t, err)
	require.Equal(t, "pending", stored.Status)
}
