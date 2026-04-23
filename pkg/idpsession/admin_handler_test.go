package idpsession

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestIdpSession(t *testing.T, userID, userAgent, ipAddress string) string {
	t.Helper()
	id := uuid.New().String()
	require.NoError(t, CreateIdpSession(IdpSession{
		ID: id, UserID: userID, UserAgent: userAgent, IPAddress: ipAddress,
	}))
	return id
}

func linkTestOAuthSession(t *testing.T, userID, idpSessionID, accessToken string) string {
	t.Helper()
	sessionID := uuid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, idp_session_id)
		VALUES (?, ?, ?, ?, '', '', '', datetime('now'), datetime('now', '+1 hour'), ?)`,
		sessionID, userID, accessToken, accessToken+"-refresh", idpSessionID,
	)
	require.NoError(t, err)
	return sessionID
}

func TestHandleListUserIdpSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestUser(t, "user2")

	idpA := createTestIdpSession(t, "user1", "Chrome/120", "10.0.0.1")
	_ = linkTestOAuthSession(t, "user1", idpA, "at-a1")
	_ = linkTestOAuthSession(t, "user1", idpA, "at-a2")
	idpB := createTestIdpSession(t, "user1", "Firefox/110", "10.0.0.2")
	_ = createTestIdpSession(t, "user2", "Safari/17", "10.0.0.3")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/api/users/{id}/idp-sessions", HandleListUserIdpSessions)

	req := httptest.NewRequest("GET", "/admin/api/users/user1/idp-sessions", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]IdpSessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)

	byID := map[string]IdpSessionResponse{}
	for _, s := range resp.Data {
		byID[s.ID] = s
	}
	assert.Equal(t, 2, byID[idpA].ActiveAppsCount)
	assert.Equal(t, 0, byID[idpB].ActiveAppsCount)
}

func TestHandleListUserIdpSessions_ExcludesDeactivated(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	active := createTestIdpSession(t, "user1", "Chrome/120", "10.0.0.1")
	dead := createTestIdpSession(t, "user1", "Firefox/110", "10.0.0.2")
	_, err := db.GetDB().Exec(
		`UPDATE idp_sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ?`, dead,
	)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/api/users/{id}/idp-sessions", HandleListUserIdpSessions)

	req := httptest.NewRequest("GET", "/admin/api/users/user1/idp-sessions", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]IdpSessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, active, resp.Data[0].ID)
}

func TestHandleListUserIdpSessions_EmptyResult(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/api/users/{id}/idp-sessions", HandleListUserIdpSessions)

	req := httptest.NewRequest("GET", "/admin/api/users/user1/idp-sessions", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]IdpSessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 0)
}

func TestHandleListIdpSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestUser(t, "user2")

	_ = createTestIdpSession(t, "user1", "Chrome/120", "10.0.0.1")
	_ = createTestIdpSession(t, "user1", "Firefox/110", "10.0.0.2")
	_ = createTestIdpSession(t, "user2", "Safari/17", "10.0.0.3")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/api/idp-sessions", HandleListIdpSessions)

	// List all
	req := httptest.NewRequest("GET", "/admin/api/idp-sessions", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]IdpSessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 3)

	// Filter by user_id
	req = httptest.NewRequest("GET", "/admin/api/idp-sessions?user_id=user1", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)
	for _, s := range resp.Data {
		assert.Equal(t, "user1", s.UserID)
	}
}

func TestHandleListIdpSessions_IncludesUserID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	id := createTestIdpSession(t, "user1", "Chrome/120", "10.0.0.1")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/api/idp-sessions", HandleListIdpSessions)

	req := httptest.NewRequest("GET", "/admin/api/idp-sessions", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]IdpSessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, id, resp.Data[0].ID)
	assert.Equal(t, "user1", resp.Data[0].UserID)
}

func TestHandleForceLogoutIdpSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	target := createTestIdpSession(t, "user1", "Chrome/120", "10.0.0.1")
	childSession := linkTestOAuthSession(t, "user1", target, "at-child")

	_, err := db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', datetime('now','+1 day'), datetime('now','+1 hour'),
		        datetime('now'), 'openid', 'authorization_code')`,
		"tok-child", "user1", "at-child", "at-child-refresh",
	)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /admin/api/idp-sessions/{id}", HandleForceLogoutIdpSession)

	req := httptest.NewRequest("DELETE", "/admin/api/idp-sessions/"+target, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var ida *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = ?`, target,
	).Scan(&ida))
	assert.NotNil(t, ida)

	var da *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM sessions WHERE id = ?`, childSession,
	).Scan(&da))
	assert.NotNil(t, da)

	var ra *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT revoked_at FROM tokens WHERE id = ?`, "tok-child",
	).Scan(&ra))
	assert.NotNil(t, ra)
}

func TestHandleForceLogoutIdpSession_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /admin/api/idp-sessions/{id}", HandleForceLogoutIdpSession)

	req := httptest.NewRequest("DELETE", "/admin/api/idp-sessions/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleForceLogoutIdpSession_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest("DELETE", "/admin/api/idp-sessions/", nil)
	rr := httptest.NewRecorder()
	HandleForceLogoutIdpSession(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
