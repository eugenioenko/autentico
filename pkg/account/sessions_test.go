package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createIdpSessionFor is a helper: inserts an active IdP session for the user.
func createIdpSessionFor(t *testing.T, usr *user.User) string {
	t.Helper()
	id := uuid.New().String()
	require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{
		ID: id, UserID: usr.ID, UserAgent: "ua", IPAddress: "127.0.0.1",
	}))
	return id
}

// linkOAuthSessionToIdp is a helper: inserts an active OAuth session row
// stamped with idp_session_id so it counts toward active_apps_count / cascade.
func linkOAuthSessionToIdp(t *testing.T, usr *user.User, idpSessionID, accessToken string) string {
	t.Helper()
	sessionID := uuid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, idp_session_id)
		VALUES (?, ?, ?, ?, '', '', '', datetime('now'), datetime('now', '+1 hour'), ?)`,
		sessionID, usr.ID, accessToken, accessToken+"-refresh", idpSessionID,
	)
	require.NoError(t, err)
	return sessionID
}

func TestHandleListSessions_ReturnsIdpSessions(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	idpA := createIdpSessionFor(t, usr)
	_ = linkOAuthSessionToIdp(t, usr, idpA, "at-a1")
	_ = linkOAuthSessionToIdp(t, usr, idpA, "at-a2")
	idpB := createIdpSessionFor(t, usr)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/sessions", HandleListSessions, token)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[[]SessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)

	byID := map[string]SessionResponse{}
	for _, s := range resp.Data {
		byID[s.ID] = s
	}
	assert.Equal(t, 2, byID[idpA].ActiveAppsCount, "IdP A should count two linked OAuth sessions")
	assert.Equal(t, 0, byID[idpB].ActiveAppsCount, "IdP B has no linked OAuth sessions")
}

func TestHandleListSessions_ExcludesDeactivatedAndOtherUsers(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	// Active IdP session for this user — must appear.
	mine := createIdpSessionFor(t, usr)

	// Deactivated IdP session for this user — must NOT appear.
	dead := createIdpSessionFor(t, usr)
	_, err := db.GetDB().Exec(
		`UPDATE idp_sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ?`, dead,
	)
	require.NoError(t, err)

	// Another user's active IdP session — must NOT appear.
	testutils.InsertTestUser(t, "other-user")
	other, err := user.UserByID("other-user")
	require.NoError(t, err)
	_ = createIdpSessionFor(t, other)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/sessions", HandleListSessions, token)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[[]SessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, mine, resp.Data[0].ID)
}

func TestHandleListSessions_MarksCurrentSessionFromCookie(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)
	current := createIdpSessionFor(t, usr)
	other := createIdpSessionFor(t, usr)

	req := httptest.NewRequest("GET", "/account/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{
		Name:  config.GetBootstrap().AuthIdpSessionCookieName,
		Value: current,
	})
	rr := httptest.NewRecorder()
	HandleListSessions(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[[]SessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	for _, s := range resp.Data {
		if s.ID == current {
			assert.True(t, s.IsCurrent)
		}
		if s.ID == other {
			assert.False(t, s.IsCurrent)
		}
	}
}

func TestHandleListSessions_ExcludesIdleExpired(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	})

	fresh := createIdpSessionFor(t, usr)

	// Simulate an IdP session that has been idle beyond the configured timeout.
	idle := createIdpSessionFor(t, usr)
	_, err := db.GetDB().Exec(
		`UPDATE idp_sessions SET last_activity_at = ? WHERE id = ?`,
		time.Now().Add(-2*time.Hour), idle,
	)
	require.NoError(t, err)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/sessions", HandleListSessions, token)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[[]SessionResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, fresh, resp.Data[0].ID, "idle-expired IdP session must be filtered out pre-cleanup")
}

func TestHandleListSessions_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/sessions", HandleListSessions, "invalid-token")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleRevokeSession_CascadesChildSessionsAndTokens(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	target := createIdpSessionFor(t, usr)
	childSession := linkOAuthSessionToIdp(t, usr, target, "at-child")
	// Also insert a token row so we can assert revocation cascade.
	_, err := db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', datetime('now','+1 day'), datetime('now','+1 hour'),
		        datetime('now'), 'openid', 'authorization_code')`,
		"tok-child", usr.ID, "at-child", "at-child-refresh",
	)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/sessions/{id}", HandleRevokeSession)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/"+target, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// IdP session deactivated.
	var ida *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM idp_sessions WHERE id = ?`, target,
	).Scan(&ida))
	assert.NotNil(t, ida)

	// Child OAuth session deactivated.
	var da *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT deactivated_at FROM sessions WHERE id = ?`, childSession,
	).Scan(&da))
	assert.NotNil(t, da)

	// Child token revoked.
	var ra *time.Time
	require.NoError(t, db.GetDB().QueryRow(
		`SELECT revoked_at FROM tokens WHERE id = ?`, "tok-child",
	).Scan(&ra))
	assert.NotNil(t, ra)
}

func TestHandleRevokeSession_CurrentDevice_ClearsCookie(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)
	current := createIdpSessionFor(t, usr)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/sessions/{id}", HandleRevokeSession)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/"+current, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{
		Name:  config.GetBootstrap().AuthIdpSessionCookieName,
		Value: current,
	})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var cleared *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == config.GetBootstrap().AuthIdpSessionCookieName {
			cleared = c
			break
		}
	}
	require.NotNil(t, cleared, "current-device revoke must emit a clear-cookie response")
	assert.True(t, cleared.MaxAge < 0)
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

func TestHandleRevokeSession_Forbidden_NotOwner(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	testutils.InsertTestUser(t, "other-user-id")
	other, err := user.UserByID("other-user-id")
	require.NoError(t, err)
	otherIdp := createIdpSessionFor(t, other)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/sessions/{id}", HandleRevokeSession)

	req := httptest.NewRequest("DELETE", "/account/api/sessions/"+otherIdp, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
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

