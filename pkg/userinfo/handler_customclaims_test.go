package userinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/userclaim"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleUserInfo_CustomClaims_Present(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, 'ccuser', 'cc@example.com', 'pass')`, userID)
	require.NoError(t, err)
	require.NoError(t, userclaim.UpsertClaim(userID, "tier", "gold"))
	require.NoError(t, userclaim.UpsertClaim(userID, "region", "eu"))

	token, err := generateTestTokensWithScope(userID, "openid custom_claims")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "gold", body["tier"])
	assert.Equal(t, "eu", body["region"])
}

func TestHandleUserInfo_CustomClaims_AbsentWithoutScope(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, 'ccuser2', 'cc2@example.com', 'pass')`, userID)
	require.NoError(t, err)
	require.NoError(t, userclaim.UpsertClaim(userID, "tier", "gold"))

	token, err := generateTestTokensWithScope(userID, "openid profile")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.NotContains(t, body, "tier")
}
