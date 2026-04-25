package deletion

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestUserAndSession(t *testing.T) (string, *user.User) {
	t.Helper()
	userID := uuid.New().String()
	testutils.InsertTestUser(t, userID)

	usr, err := user.UserByID(userID)
	require.NoError(t, err)

	sessionID := uuid.New().String()
	claims := &jwtutil.AccessTokenClaims{
		UserID:    usr.ID,
		SessionID: sessionID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := tok.SignedString(key.GetPrivateKey())
	require.NoError(t, err)

	sess := session.Session{
		ID:           sessionID,
		UserID:       usr.ID,
		AccessToken:  tokenString,
		RefreshToken: "test-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	require.NoError(t, session.CreateSession(sess))

	// Persist matching tokens row (active) so the revocation read-layer
	// filter sees an active record for this bearer.
	now := time.Now().UTC()
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', ?, ?, ?, 'openid', 'password')
	`, "tok-"+sessionID[:8], usr.ID, tokenString, "refresh-"+sessionID[:8], now.Add(time.Hour), now.Add(time.Hour), now)
	require.NoError(t, err)

	return tokenString, usr
}

// --- HandleRequestDeletion ---

func TestHandleRequestDeletion_AdminApprovalMode(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	rr := testutils.MockApiRequestWithAuth(t, `{}`, "POST", "/account/api/deletion-request", HandleRequestDeletion, token)
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp model.ApiResponse[DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, usr.ID, resp.Data.UserID)
}

func TestHandleRequestDeletion_WithReason(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	rr := testutils.MockApiRequestWithAuth(t, `{"reason":"no longer needed"}`, "POST", "/account/api/deletion-request", HandleRequestDeletion, token)
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp model.ApiResponse[DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, usr.ID, resp.Data.UserID)
	require.NotNil(t, resp.Data.Reason)
	assert.Equal(t, "no longer needed", *resp.Data.Reason)
}

func TestHandleRequestDeletion_SelfServiceMode(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	testutils.WithConfigOverride(t, func() {
		config.Values.AllowSelfServiceDeletion = true
	})

	rr := testutils.MockApiRequestWithAuth(t, `{}`, "POST", "/account/api/deletion-request", HandleRequestDeletion, token)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	deleted, err := user.UserByID(usr.ID)
	assert.Error(t, err)
	assert.Nil(t, deleted)
}

func TestHandleRequestDeletion_AlreadyPending(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_, err := CreateDeletionRequest(usr.ID, nil)
	require.NoError(t, err)

	rr := testutils.MockApiRequestWithAuth(t, `{}`, "POST", "/account/api/deletion-request", HandleRequestDeletion, token)
	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestHandleRequestDeletion_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	rr := testutils.MockApiRequestWithAuth(t, `{}`, "POST", "/account/api/deletion-request", HandleRequestDeletion, "bad-token")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- HandleGetDeletionRequest ---

func TestHandleGetDeletionRequest_NoPendingRequest(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/deletion-request", HandleGetDeletionRequest, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleGetDeletionRequest_Found(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	reason := "testing"
	_, err := CreateDeletionRequest(usr.ID, &reason)
	require.NoError(t, err)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/deletion-request", HandleGetDeletionRequest, token)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[DeletionRequestResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, usr.ID, resp.Data.UserID)
	require.NotNil(t, resp.Data.Reason)
	assert.Equal(t, "testing", *resp.Data.Reason)
}

func TestHandleGetDeletionRequest_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/deletion-request", HandleGetDeletionRequest, "bad-token")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- HandleCancelDeletionRequest ---

func TestHandleCancelDeletionRequest_Success(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_, err := CreateDeletionRequest(usr.ID, nil)
	require.NoError(t, err)

	rr := testutils.MockApiRequestWithAuth(t, "", "DELETE", "/account/api/deletion-request", HandleCancelDeletionRequest, token)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	req, err := DeletionRequestByUserID(usr.ID)
	require.NoError(t, err)
	assert.Nil(t, req)
}

func TestHandleCancelDeletionRequest_NotFound(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	rr := testutils.MockApiRequestWithAuth(t, "", "DELETE", "/account/api/deletion-request", HandleCancelDeletionRequest, token)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleCancelDeletionRequest_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	rr := testutils.MockApiRequestWithAuth(t, "", "DELETE", "/account/api/deletion-request", HandleCancelDeletionRequest, "bad-token")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- HandleListDeletionRequests ---

func TestHandleListDeletionRequests_Empty(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest("GET", "/admin/api/deletion-requests", nil)
	rr := httptest.NewRecorder()
	HandleListDeletionRequests(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[model.ListResponse[DeletionRequestResponse]]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Empty(t, resp.Data.Items)
	assert.Equal(t, 0, resp.Data.Total)
}

func TestHandleListDeletionRequests_WithRequests(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr1 := setupTestUserAndSession(t)
	_, usr2 := setupTestUserAndSession(t)

	_, err := CreateDeletionRequest(usr1.ID, nil)
	require.NoError(t, err)
	reason := "cleanup"
	_, err = CreateDeletionRequest(usr2.ID, &reason)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/admin/api/deletion-requests", nil)
	rr := httptest.NewRecorder()
	HandleListDeletionRequests(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[model.ListResponse[DeletionRequestResponse]]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data.Items, 2)
	assert.Equal(t, 2, resp.Data.Total)
	assert.NotEmpty(t, resp.Data.Items[0].Username)
	assert.NotEmpty(t, resp.Data.Items[0].Email)
}

func TestHandleListDeletionRequests_Search(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr1 := setupTestUserAndSession(t)
	_, usr2 := setupTestUserAndSession(t)

	_, err := CreateDeletionRequest(usr1.ID, nil)
	require.NoError(t, err)
	reason := "cleanup"
	_, err = CreateDeletionRequest(usr2.ID, &reason)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/admin/api/deletion-requests?search="+usr1.Username, nil)
	rr := httptest.NewRecorder()
	HandleListDeletionRequests(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[model.ListResponse[DeletionRequestResponse]]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data.Items, 1)
	assert.Equal(t, usr1.ID, resp.Data.Items[0].UserID)
}

func TestHandleListDeletionRequests_SortByUsername(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr1 := setupTestUserAndSession(t)
	_, usr2 := setupTestUserAndSession(t)

	_, err := CreateDeletionRequest(usr1.ID, nil)
	require.NoError(t, err)
	_, err = CreateDeletionRequest(usr2.ID, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/admin/api/deletion-requests?sort=username&order=asc", nil)
	rr := httptest.NewRecorder()
	HandleListDeletionRequests(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[model.ListResponse[DeletionRequestResponse]]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data.Items, 2)
	assert.True(t, resp.Data.Items[0].Username <= resp.Data.Items[1].Username)
}

func TestHandleListDeletionRequests_Pagination(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr1 := setupTestUserAndSession(t)
	_, usr2 := setupTestUserAndSession(t)

	_, err := CreateDeletionRequest(usr1.ID, nil)
	require.NoError(t, err)
	_, err = CreateDeletionRequest(usr2.ID, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/admin/api/deletion-requests?limit=1&offset=0", nil)
	rr := httptest.NewRecorder()
	HandleListDeletionRequests(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[model.ListResponse[DeletionRequestResponse]]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data.Items, 1)
	assert.Equal(t, 2, resp.Data.Total)
}

// --- HandleApproveDeletionRequest ---

func TestHandleApproveDeletionRequest_Success(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr := setupTestUserAndSession(t)

	dr, err := CreateDeletionRequest(usr.ID, nil)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/api/deletion-requests/{id}/approve", HandleApproveDeletionRequest)

	req := httptest.NewRequest("POST", "/admin/api/deletion-requests/"+dr.ID+"/approve", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	deleted, err := user.UserByID(usr.ID)
	assert.Error(t, err)
	assert.Nil(t, deleted)
}

func TestHandleApproveDeletionRequest_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/api/deletion-requests/{id}/approve", HandleApproveDeletionRequest)

	req := httptest.NewRequest("POST", "/admin/api/deletion-requests/nonexistent/approve", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- HandleAdminCancelDeletionRequest ---

func TestHandleAdminCancelDeletionRequest_Success(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr := setupTestUserAndSession(t)

	dr, err := CreateDeletionRequest(usr.ID, nil)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /admin/api/deletion-requests/{id}", HandleAdminCancelDeletionRequest)

	req := httptest.NewRequest("DELETE", "/admin/api/deletion-requests/"+dr.ID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	remaining, err := DeletionRequestByUserID(usr.ID)
	require.NoError(t, err)
	assert.Nil(t, remaining)

	// User should still exist
	existing, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	assert.NotNil(t, existing)
}

func TestHandleAdminCancelDeletionRequest_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /admin/api/deletion-requests/{id}", HandleAdminCancelDeletionRequest)

	req := httptest.NewRequest("DELETE", "/admin/api/deletion-requests/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}
