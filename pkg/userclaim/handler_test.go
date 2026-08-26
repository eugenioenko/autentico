package userclaim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func upsertReq(t *testing.T, userID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/"+userID+"/claims", bytes.NewBuffer(raw))
	req.SetPathValue("id", userID)
	rr := httptest.NewRecorder()
	HandleUpsertUserClaim(rr, req)
	return rr
}

func TestHandleUpsertUserClaim_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	rr := upsertReq(t, "user1", UserClaimRequest{Name: "tier", Value: "gold"})
	assert.Equal(t, http.StatusCreated, rr.Code)

	claims, err := ClaimsByUserID("user1")
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, "gold", claims[0].Value)
}

func TestHandleUpsertUserClaim_UpdatesExisting(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	assert.Equal(t, http.StatusCreated, upsertReq(t, "user1", UserClaimRequest{Name: "tier", Value: "silver"}).Code)
	assert.Equal(t, http.StatusCreated, upsertReq(t, "user1", UserClaimRequest{Name: "tier", Value: "gold"}).Code)

	claims, _ := ClaimsByUserID("user1")
	require.Len(t, claims, 1)
	assert.Equal(t, "gold", claims[0].Value)
}

func TestHandleUpsertUserClaim_ReservedName(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	rr := upsertReq(t, "user1", UserClaimRequest{Name: "email", Value: "x"})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp model.AuthErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Contains(t, resp.ErrorDescription, "reserved")
}

func TestHandleUpsertUserClaim_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/user1/claims", bytes.NewBufferString("not-json"))
	req.SetPathValue("id", "user1")
	rr := httptest.NewRecorder()
	HandleUpsertUserClaim(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleUpsertUserClaim_UnknownUser(t *testing.T) {
	testutils.WithTestDB(t)

	rr := upsertReq(t, "ghost", UserClaimRequest{Name: "tier", Value: "gold"})
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleListUserClaims_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	require.NoError(t, UpsertClaim("user1", "tier", "gold"))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/user1/claims", nil)
	req.SetPathValue("id", "user1")
	rr := httptest.NewRecorder()
	HandleListUserClaims(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]UserClaimResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "tier", resp.Data[0].Name)
}

func TestHandleListUserClaims_EmptyIsArray(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/user1/claims", nil)
	req.SetPathValue("id", "user1")
	rr := httptest.NewRecorder()
	HandleListUserClaims(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"data":[]`)
}

func TestHandleDeleteUserClaim_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	require.NoError(t, UpsertClaim("user1", "tier", "gold"))

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/user1/claims/tier", nil)
	req.SetPathValue("id", "user1")
	req.SetPathValue("name", "tier")
	rr := httptest.NewRecorder()
	HandleDeleteUserClaim(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	claims, _ := ClaimsByUserID("user1")
	assert.Empty(t, claims)
}

func TestHandleDeleteUserClaim_NotFound(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/user1/claims/tier", nil)
	req.SetPathValue("id", "user1")
	req.SetPathValue("name", "tier")
	rr := httptest.NewRecorder()
	HandleDeleteUserClaim(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleDeleteUserClaim_NamespacedName(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	require.NoError(t, UpsertClaim("user1", "https://app.example.com/tier", "gold"))

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/user1/claims/https://app.example.com/tier", nil)
	req.SetPathValue("id", "user1")
	req.SetPathValue("name", "https://app.example.com/tier")
	rr := httptest.NewRecorder()
	HandleDeleteUserClaim(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
