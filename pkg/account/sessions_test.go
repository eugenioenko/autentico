package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/session"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListSessions(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	sessID := "deactivated-1"
	sess := session.Session{
		ID:           sessID,
		UserID:       usr.ID,
		AccessToken:  "token-deact",
		RefreshToken: "refresh-deact",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = session.CreateSession(sess)
	_, _ = db.GetDB().Exec("UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ?", sessID)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/sessions", HandleListSessions, token)
	assert.Equal(t, http.StatusOK, rr.Code)
	
	var resp model.ApiResponse[[]SessionResponse]
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Len(t, resp.Data, 1)
}

func TestHandleListSessions_TokenClaimsError(t *testing.T) {
	testutils.WithTestDB(t)
	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/sessions", HandleListSessions, "invalid-token")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleRevokeSession(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	otherSessionID := uuid.New().String()
	sess := session.Session{
		ID:           otherSessionID,
		UserID:       usr.ID,
		AccessToken:  "other-token",
		RefreshToken: "other-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = session.CreateSession(sess)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/sessions/{id}", HandleRevokeSession)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/"+otherSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Revoke current session
	claims, _ := jwtutil.ValidateAccessToken(token)
	req = httptest.NewRequest("DELETE", "/account/api/sessions/"+claims.SessionID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRevokeSession_NotFound(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/sessions/{id}", HandleRevokeSession)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleRevokeSession_InvalidPath(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)
	
	req := httptest.NewRequest("DELETE", "/account/api/sessions/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleRevokeSession(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRevokeSession_NotOwned(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	// Create another user and their session
	testutils.InsertTestUser(t, "other")
	_, _ = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at) 
		VALUES ('s-other', 'other', 'a-other', 'r-other', '', '', '', datetime('now'), datetime('now', '+1 hour'))`)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/sessions/{id}", HandleRevokeSession)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/s-other", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleListSessions_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	req := httptest.NewRequest("GET", "/account/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleListSessions(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var listResp model.ApiResponse[[]SessionResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &listResp)
	require.NoError(t, err)
	assert.Len(t, listResp.Data, 1)
}

func TestHandleRevokeSession_MissingID(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleRevokeSession(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing session ID")
}

func TestHandleRevokeSession_Success_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	// Create another session to revoke with all NOT NULL fields
	_, err := db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at) 
		VALUES ('s2', ?, 'a2', 'r2', '', '', '', datetime('now'), datetime('now', '+1 hour'))`, u.ID)
	assert.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/sessions/{id}", HandleRevokeSession)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/s2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
