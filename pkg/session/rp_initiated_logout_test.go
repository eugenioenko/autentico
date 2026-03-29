package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestClient inserts a minimal OAuth2 client with the given post-logout redirect URIs.
func createTestClient(t *testing.T, clientID string, postLogoutURIs []string) {
	t.Helper()
	urisJSON := `[]`
	if len(postLogoutURIs) > 0 {
		b := `[`
		for i, u := range postLogoutURIs {
			if i > 0 {
				b += ","
			}
			b += `"` + u + `"`
		}
		b += `]`
		urisJSON = b
	}
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris,
		                     post_logout_redirect_uris, grant_types, response_types,
		                     scopes, token_endpoint_auth_method, is_active)
		VALUES (?, ?, ?, 'public', '["https://example.com/callback"]',
		        ?, '["authorization_code"]', '["code"]',
		        'openid', 'none', 1)
	`, xid.New().String(), clientID, "Test Client "+clientID, urisJSON)
	require.NoError(t, err)
}

func TestHandleRpInitiatedLogout_NoParams_RedirectsToRoot(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/", rr.Header().Get("Location"))
}

func TestHandleRpInitiatedLogout_ClearsIdpSessionCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	})

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "rplogoutuser", "rplogout@example.com", "hash")
	require.NoError(t, err)

	idpSessionID := xid.New().String()
	err = idpsession.CreateIdpSession(idpsession.IdpSession{
		ID: idpSessionID, UserID: userID, UserAgent: "ua", IPAddress: "127.0.0.1",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	req.AddCookie(&http.Cookie{Name: config.GetBootstrap().AuthIdpSessionCookieName, Value: idpSessionID})
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	var cleared *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == config.GetBootstrap().AuthIdpSessionCookieName {
			cleared = c
			break
		}
	}
	require.NotNil(t, cleared, "IdP session cookie should be cleared")
	assert.True(t, cleared.MaxAge < 0, "cookie MaxAge should be negative to clear it")
}

func TestHandleRpInitiatedLogout_WithIdTokenHint_DeactivatesSessions(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "rphintuser", "rphint@example.com", "hash")
	require.NoError(t, err)

	// Create an active OAuth session for the user.
	accessToken, sessionID, err := generateTestAccessToken(userID)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint="+url.QueryEscape(accessToken), nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	// Session should be deactivated.
	var deactivatedAt interface{}
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = ?`, sessionID).Scan(&deactivatedAt)
	require.NoError(t, err)
	assert.NotNil(t, deactivatedAt, "session should be deactivated")
}

func TestHandleRpInitiatedLogout_ValidPostLogoutRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)

	clientID := "test-rp-logout-client"
	postLogoutURI := "https://myapp.example.com/logged-out"
	createTestClient(t, clientID, []string{postLogoutURI})

	target := "/oauth2/logout?" + url.Values{
		"client_id":               {clientID},
		"post_logout_redirect_uri": {postLogoutURI},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, postLogoutURI, rr.Header().Get("Location"))
}

func TestHandleRpInitiatedLogout_ValidPostLogoutRedirectURIWithState(t *testing.T) {
	testutils.WithTestDB(t)

	clientID := "test-rp-logout-state-client"
	postLogoutURI := "https://myapp.example.com/logged-out"
	createTestClient(t, clientID, []string{postLogoutURI})

	target := "/oauth2/logout?" + url.Values{
		"client_id":               {clientID},
		"post_logout_redirect_uri": {postLogoutURI},
		"state":                   {"abc123"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, postLogoutURI+"?state=abc123", rr.Header().Get("Location"))
}

func TestHandleRpInitiatedLogout_UnregisteredPostLogoutRedirectURI_RedirectsToRoot(t *testing.T) {
	testutils.WithTestDB(t)

	clientID := "test-rp-logout-unregistered"
	createTestClient(t, clientID, []string{"https://allowed.example.com/out"})

	target := "/oauth2/logout?" + url.Values{
		"client_id":               {clientID},
		"post_logout_redirect_uri": {"https://evil.example.com/steal"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/", rr.Header().Get("Location"), "unregistered URI must be rejected")
}

func TestHandleRpInitiatedLogout_UnknownClientID_RedirectsToRoot(t *testing.T) {
	testutils.WithTestDB(t)

	target := "/oauth2/logout?" + url.Values{
		"client_id":               {"nonexistent-client"},
		"post_logout_redirect_uri": {"https://example.com/out"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/", rr.Header().Get("Location"))
}

func TestHandleRpInitiatedLogout_ClientIdFromIdTokenHint(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "rpazpuser", "rpazp@example.com", "hash")
	require.NoError(t, err)

	// The access token carries the configured audience as "aud".
	// Register a client with that audience as client_id.
	aud := config.Get().AuthAccessTokenAudience
	clientIDFromAud := ""
	if len(aud) > 0 {
		clientIDFromAud = aud[0]
	}

	postLogoutURI := "https://myapp.example.com/done"
	if clientIDFromAud != "" {
		// Only run the redirect assertion when a real client_id can be derived.
		createTestClient(t, clientIDFromAud, []string{postLogoutURI})
	}

	accessToken, _, err := generateTestAccessToken(userID)
	require.NoError(t, err)

	target := "/oauth2/logout?" + url.Values{
		"id_token_hint":            {accessToken},
		"post_logout_redirect_uri": {postLogoutURI},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	if clientIDFromAud != "" {
		assert.Equal(t, postLogoutURI, rr.Header().Get("Location"))
	} else {
		assert.Equal(t, "/", rr.Header().Get("Location"))
	}
}

func TestHandleRpInitiatedLogout_InvalidIdTokenHint_StillLoggedOut(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint=not-a-valid-jwt", nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	// Should still redirect (gracefully, no 4xx)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/", rr.Header().Get("Location"))
}

