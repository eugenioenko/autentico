package account

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListApps(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)
	for _, c := range []struct {
		id, name, redirects string
		active              bool
	}{
		{"app-a", "Alpha", `["https://alpha.example.com/auth/callback"]`, true},
		{"app-b", "Beta", `["http://localhost:3000/callback"]`, true},
		{"app-c", "Disabled", `["https://disabled.example.com/callback"]`, false},
		{config.AdminClientID, "Admin", `["https://admin.example.com/callback"]`, true},
		{config.AccountClientID, "Account", `["https://account.example.com/callback"]`, true},
	} {
		_, err := db.GetDB().Exec(`INSERT INTO clients (id, client_id, client_name, redirect_uris, is_active) VALUES (?, ?, ?, ?, ?)`, c.id, c.id, c.name, c.redirects, c.active)
		require.NoError(t, err)
	}

	rr := mockAuthRequest(t, "", http.MethodGet, "/account/api/apps", HandleListApps, info)
	require.Equal(t, http.StatusOK, rr.Code)
	var response struct {
		Data []AppResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	require.Len(t, response.Data, 2)
	assert.Equal(t, AppResponse{ClientID: "app-a", ClientName: "Alpha", OpenURL: "https://alpha.example.com/"}, response.Data[0])
	assert.Equal(t, AppResponse{ClientID: "app-b", ClientName: "Beta", OpenURL: "http://localhost:3000/"}, response.Data[1])

	unauthorized := mockAuthRequest(t, "", http.MethodGet, "/account/api/apps", HandleListApps, nil)
	assert.Equal(t, http.StatusUnauthorized, unauthorized.Code)
}

func TestAppOrigin(t *testing.T) {
	assert.Empty(t, appOrigin(`["javascript:alert(1)"]`))
	assert.Empty(t, appOrigin(`["http://example.com/callback"]`))
	assert.Empty(t, appOrigin(`["https://user:pass@example.com/callback"]`))
	assert.Equal(t, "https://app.example.com/", appOrigin(`["javascript:alert(1)","https://app.example.com/callback"]`))
}
