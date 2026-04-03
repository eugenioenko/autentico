package session

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/key"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestAccessToken creates a valid JWT access token for testing
func generateTestAccessToken(userID string) (string, string, error) {
	return generateTestAccessTokenWithAzp(userID, "")
}

// generateTestAccessTokenWithAzp creates a valid JWT with a specific azp (authorized party) claim.
func generateTestAccessTokenWithAzp(userID, azp string) (string, string, error) {
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()

	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   sessionID,
		"scope": "openid profile email",
	}
	if azp != "" {
		accessClaims["azp"] = azp
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signedToken, err := accessToken.SignedString(key.GetPrivateKey())
	return signedToken, sessionID, err
}

func TestHandleLogout(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user directly in the database
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "logoutuser", "logout@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate a real JWT token
	accessToken, sessionID, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	// Insert a session with the real access token
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	assert.NoError(t, err)

	// Perform logout with the real JWT token
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify the session is deactivated
	var deactivatedAt sql.NullTime
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = ?`, sessionID).Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.True(t, deactivatedAt.Valid, "deactivated_at should be set")
}

func TestHandleLogout_NoAuthNoParams_ShowsLogoutPage(t *testing.T) {
	// RP-Initiated Logout 1.0 §2: POST with no params is a valid logout request.
	// The OP renders a signed-out page (no error).
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "signed out")
}

func TestHandleLogoutInvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or expired token")
}

func TestHandleLogout_BasicAuth_FallsThrough(t *testing.T) {
	// RP-Initiated Logout 1.0 §2: Basic Auth is not part of the spec.
	// When a non-Bearer Authorization header is present, the handler falls
	// through to RP-Initiated Logout form-param processing.
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	// Falls through to spec path, renders logout page (no error).
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "signed out")
}

func TestHandleLogout_ClearsIdpSessionCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	})

	// Create user
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "logoutuser", "logout@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate token and create session
	accessToken, sessionID, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	assert.NoError(t, err)

	// Create an IdP session
	idpSessionID := xid.New().String()
	err = idpsession.CreateIdpSession(idpsession.IdpSession{
		ID:        idpSessionID,
		UserID:    userID,
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})
	assert.NoError(t, err)

	// Build request with IdP session cookie and auth header
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.AddCookie(&http.Cookie{
		Name:  config.GetBootstrap().AuthIdpSessionCookieName,
		Value: idpSessionID,
	})
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify IdP session cookie is cleared
	cookies := rr.Result().Cookies()
	var clearedCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == config.GetBootstrap().AuthIdpSessionCookieName {
			clearedCookie = c
			break
		}
	}
	assert.NotNil(t, clearedCookie, "should set a clear-cookie header for IdP session")
	assert.True(t, clearedCookie.MaxAge < 0, "cookie MaxAge should be negative to clear it")

	// Verify IdP session is deactivated in DB
	_, err = idpsession.IdpSessionByID(idpSessionID)
	assert.Error(t, err, "deactivated IdP session should not be found")
}

// TestHandleLogout_RevokesIdpSessionWithoutCookie covers the bug where a server-side
// logout (Bearer token only, no browser cookie) left the IdP session active, allowing
// the user to be silently re-authenticated on the next authorize request.
func TestHandleLogout_RevokesIdpSessionWithoutCookie(t *testing.T) {
	testutils.WithTestDB(t)

	// Create user
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "logoutuser2", "logout2@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate token and create session
	accessToken, sessionID, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	assert.NoError(t, err)

	// Create an active IdP session in the DB
	idpSessionID := xid.New().String()
	err = idpsession.CreateIdpSession(idpsession.IdpSession{
		ID:        idpSessionID,
		UserID:    userID,
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})
	assert.NoError(t, err)

	// Logout without sending the IdP session cookie (simulates server-side logout)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// IdP session must be deactivated even though no cookie was present
	_, err = idpsession.IdpSessionByID(idpSessionID)
	assert.Error(t, err, "IdP session should be deactivated even when no cookie is sent")
}

func TestHandleLogout_NoIdpSession(t *testing.T) {
	testutils.WithTestDB(t)

	// Create user
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "logoutuser", "logout@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate token and create session
	accessToken, sessionID, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	assert.NoError(t, err)

	// Logout without IdP session cookie
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify session is deactivated
	var deactivatedAt sql.NullTime
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = ?`, sessionID).Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.True(t, deactivatedAt.Valid, "session should be deactivated")
}

// --- POST RP-Initiated Logout spec compliance tests ---

func TestHandleLogout_POST_WithIdTokenHint_DeactivatesSessions(t *testing.T) {
	// RP-Initiated Logout 1.0 §2: POST with id_token_hint deactivates sessions.
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "posthintuser", "posthint@example.com", "hash")
	require.NoError(t, err)

	accessToken, sessionID, err := generateTestAccessToken(userID)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	form := url.Values{"id_token_hint": {accessToken}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "signed out")

	var deactivatedAt interface{}
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = ?`, sessionID).Scan(&deactivatedAt)
	require.NoError(t, err)
	assert.NotNil(t, deactivatedAt, "session should be deactivated via POST id_token_hint")
}

func TestHandleLogout_POST_WithPostLogoutRedirectURI(t *testing.T) {
	// RP-Initiated Logout 1.0 §3: POST with registered post_logout_redirect_uri redirects.
	testutils.WithTestDB(t)

	clientID := "post-logout-redirect-client"
	postLogoutURI := "https://myapp.example.com/logged-out"
	createTestClient(t, clientID, []string{postLogoutURI})

	form := url.Values{
		"client_id":                {clientID},
		"post_logout_redirect_uri": {postLogoutURI},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, postLogoutURI, rr.Header().Get("Location"))
}

func TestHandleLogout_POST_WithPostLogoutRedirectURIAndState(t *testing.T) {
	// RP-Initiated Logout 1.0 §2: state is passed through to post_logout_redirect_uri.
	testutils.WithTestDB(t)

	clientID := "post-logout-state-client"
	postLogoutURI := "https://myapp.example.com/logged-out"
	createTestClient(t, clientID, []string{postLogoutURI})

	form := url.Values{
		"client_id":                {clientID},
		"post_logout_redirect_uri": {postLogoutURI},
		"state":                    {"mystate123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, postLogoutURI+"?state=mystate123", rr.Header().Get("Location"))
}

func TestHandleLogout_POST_UnregisteredRedirectURI_ShowsLogoutPage(t *testing.T) {
	// RP-Initiated Logout 1.0 §3: OP MUST NOT redirect if URI does not match a registered value.
	testutils.WithTestDB(t)

	clientID := "post-unregistered-uri-client"
	createTestClient(t, clientID, []string{"https://allowed.example.com/out"})

	form := url.Values{
		"client_id":                {clientID},
		"post_logout_redirect_uri": {"https://evil.example.com/steal"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "unregistered URI must be rejected, fallback to logout page")
	assert.Contains(t, rr.Body.String(), "signed out")
}

func TestHandleLogout_POST_BasicAuthWithIdTokenHint(t *testing.T) {
	// GitHub issue #131: Basic Auth header should not prevent form-param logout.
	// When a non-Bearer Authorization header is present, the handler falls through
	// to RP-Initiated Logout processing with form params.
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "basicauthuser", "basicauth@example.com", "hash")
	require.NoError(t, err)

	accessToken, sessionID, err := generateTestAccessToken(userID)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	form := url.Values{"id_token_hint": {accessToken}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("someclient", "somesecret")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var deactivatedAt interface{}
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = ?`, sessionID).Scan(&deactivatedAt)
	require.NoError(t, err)
	assert.NotNil(t, deactivatedAt, "session should be deactivated via POST with BasicAuth + id_token_hint")
}

func TestHandleLogout_POST_ClearsIdpSessionCookie(t *testing.T) {
	// RP-Initiated Logout 1.0 §2: IdP session cookie must be cleared even without id_token_hint.
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
	})

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "postidpuser", "postidp@example.com", "hash")
	require.NoError(t, err)

	idpSessionID := xid.New().String()
	err = idpsession.CreateIdpSession(idpsession.IdpSession{
		ID: idpSessionID, UserID: userID, UserAgent: "ua", IPAddress: "127.0.0.1",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.AddCookie(&http.Cookie{Name: config.GetBootstrap().AuthIdpSessionCookieName, Value: idpSessionID})
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var cleared *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == config.GetBootstrap().AuthIdpSessionCookieName {
			cleared = c
			break
		}
	}
	require.NotNil(t, cleared, "IdP session cookie should be cleared on POST logout")
	assert.True(t, cleared.MaxAge < 0, "cookie MaxAge should be negative to clear it")
}

// --- client_id vs id_token_hint mismatch tests (applies to both GET and POST) ---

func TestRpInitiatedLogout_ClientIdMismatch_NoRedirect(t *testing.T) {
	// RP-Initiated Logout 1.0 §2: When both client_id and id_token_hint are present,
	// the OP MUST verify the Client Identifier matches. On mismatch, §4 says the OP
	// MUST NOT perform post-logout redirection.
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "mismatchuser", "mismatch@example.com", "hash")
	require.NoError(t, err)

	// Token has azp="real-client", but we'll pass client_id="wrong-client-id".
	accessToken, _, err := generateTestAccessTokenWithAzp(userID, "real-client")
	require.NoError(t, err)

	wrongClientID := "wrong-client-id"
	postLogoutURI := "https://myapp.example.com/logged-out"
	createTestClient(t, wrongClientID, []string{postLogoutURI})

	// GET variant
	target := "/oauth2/logout?" + url.Values{
		"id_token_hint":            {accessToken},
		"client_id":                {wrongClientID},
		"post_logout_redirect_uri": {postLogoutURI},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	HandleRpInitiatedLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "client_id mismatch must prevent redirect")
	assert.Contains(t, rr.Body.String(), "signed out")
}

func TestRpInitiatedLogout_ClientIdMismatch_POST_NoRedirect(t *testing.T) {
	// RP-Initiated Logout 1.0 §2 + §4: same mismatch validation applies to POST.
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "mismatchuser2", "mismatch2@example.com", "hash")
	require.NoError(t, err)

	// Token has azp="real-client-post", but we'll pass client_id="wrong-client-id-post".
	accessToken, _, err := generateTestAccessTokenWithAzp(userID, "real-client-post")
	require.NoError(t, err)

	wrongClientID := "wrong-client-id-post"
	postLogoutURI := "https://myapp.example.com/logged-out"
	createTestClient(t, wrongClientID, []string{postLogoutURI})

	form := url.Values{
		"id_token_hint":            {accessToken},
		"client_id":                {wrongClientID},
		"post_logout_redirect_uri": {postLogoutURI},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "client_id mismatch must prevent redirect on POST")
	assert.Contains(t, rr.Body.String(), "signed out")
}
