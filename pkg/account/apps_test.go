package account

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/client"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListApps(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	_, err := client.CreateClientWithID("wiki", client.ClientCreateRequest{
		ClientName:    "Wiki",
		RedirectURIs:  []string{"https://wiki.example.com/callback"},
		Description:   "Team wiki",
		LogoURI:       "https://wiki.example.com/logo.png",
		ClientURI:     "https://wiki.example.com",
		ShowInAccount: true,
	})
	require.NoError(t, err)
	_, err = client.CreateClientWithID("backend", client.ClientCreateRequest{
		ClientName:   "Backend",
		RedirectURIs: []string{"https://backend.example.com/callback"},
	})
	require.NoError(t, err)

	rr := mockAuthRequest(t, "", http.MethodGet, "/account/api/apps", HandleListApps, info)
	require.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Data []AppResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, []AppResponse{{
		ClientID:    "wiki",
		Name:        "Wiki",
		Description: "Team wiki",
		LogoURI:     "https://wiki.example.com/logo.png",
		ClientURI:   "https://wiki.example.com",
	}}, response.Data)
}

func TestHandleListApps_Empty(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	rr := mockAuthRequest(t, "", http.MethodGet, "/account/api/apps", HandleListApps, info)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `[]`, string(mustData(t, rr.Body.Bytes())))
}

func TestHandleListApps_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)

	rr := mockAuthRequest(t, "", http.MethodGet, "/account/api/apps", HandleListApps, nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func mustData(t *testing.T, body []byte) json.RawMessage {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	return envelope.Data
}
