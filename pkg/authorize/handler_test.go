package authorize

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleAuthorize(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
	assert.Contains(t, rr.Body.String(), "username")
	assert.Contains(t, rr.Body.String(), "password")
}

func TestHandleAuthorize_PostRedirectsToGet(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	body := "response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz&nonce=abc"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// POST must redirect to GET so the CSRF middleware can set the cookie
	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "/oauth2/authorize")
	assert.Contains(t, loc, "response_type=code")
	assert.Contains(t, loc, "client_id=test-client")
	assert.Contains(t, loc, "state=xyz")
	assert.Contains(t, loc, "nonce=abc")
}

func TestHandleAuthorize_PostInvalidClient_ShowsError(t *testing.T) {
	testutils.WithTestDB(t)

	body := "response_type=code&client_id=nonexistent&redirect_uri=http://localhost/callback&state=xyz"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Invalid client must show error page, not redirect
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unknown client_id")
}

func TestHandleAuthorize_UnknownClientID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=nonexistent-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unknown client_id")
}

func TestHandleAuthorize_MissingResponseType(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Must redirect back with error=invalid_request
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=invalid_request")
	assert.Contains(t, rr.Header().Get("Location"), "state=xyz123")
}

func TestHandleAuthorize_InvalidResponseType(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=token&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Must redirect back with error=unsupported_response_type
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=unsupported_response_type")
}

func TestHandleAuthorize_InvalidRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=not-a-valid-uri&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Cannot redirect — show error page
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect_uri")
}

func TestHandleAuthorize_RedirectURIInvalid(t *testing.T) {
	testutils.WithTestDB(t)

	// A URI with no host is syntactically invalid — show error page, cannot redirect
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=not-a-valid-uri&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect_uri")
}

func TestHandleAuthorize_InactiveClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert an inactive client
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, is_active)
		VALUES ('id-1', 'inactive-client', 'Test Client', 'public', '["http://localhost/callback"]', '[]', FALSE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=inactive-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Client is inactive")
}

func TestHandleAuthorize_RedirectURINotAllowed(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a client with specific allowed redirect URIs
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, is_active)
		VALUES ('id-2', 'strict-client', 'Test Client', 'confidential', '["http://allowed.com/callback"]', '[]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=strict-client&redirect_uri=http://notallowed.com/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Redirect URI not allowed")
}

func TestHandleAuthorize_ResponseTypeNotAllowed(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a client with only token response type allowed
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, response_types, is_active)
		VALUES ('id-3', 'token-only-client', 'Test Client', 'public', '["http://localhost/callback"]', '[]', '["token"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=token-only-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=unsupported_response_type")
}

func TestHandleAuthorize_AutoLogin_ValidSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	// Create a user in the DB
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES ('user-1', 'testuser', 'test@example.com', 'hashed')`)
	assert.NoError(t, err)

	// Create an IdP session
	session := idpsession.IdpSession{
		ID:        "idp-auto-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err = idpsession.CreateIdpSession(session)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-auto-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Should redirect with auth code
	assert.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	assert.Contains(t, location, "http://localhost/callback")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "state=xyz123")
}

func TestHandleAuthorize_AutoLogin_Disabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 0 // disabled
	})

	// Create a user and IdP session
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES ('user-1', 'testuser', 'test@example.com', 'hashed')`)
	assert.NoError(t, err)

	session := idpsession.IdpSession{
		ID:        "idp-disabled-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err = idpsession.CreateIdpSession(session)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-disabled-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Should show login form, not redirect
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
	assert.Contains(t, rr.Body.String(), "username")
}

func TestHandleAuthorize_AutoLogin_ExpiredSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES ('user-1', 'testuser', 'test@example.com', 'hashed')`)
	assert.NoError(t, err)

	session := idpsession.IdpSession{
		ID:        "idp-expired-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err = idpsession.CreateIdpSession(session)
	assert.NoError(t, err)

	// Set last_activity_at to 1 hour ago (beyond 30 min idle time)
	_, err = db.GetDB().Exec(`UPDATE idp_sessions SET last_activity_at = datetime('now', '-1 hour') WHERE id = 'idp-expired-1'`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-expired-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Should show login form since last activity was too long ago
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_AutoLogin_DeactivatedSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES ('user-1', 'testuser', 'test@example.com', 'hashed')`)
	assert.NoError(t, err)

	session := idpsession.IdpSession{
		ID:        "idp-deact-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err = idpsession.CreateIdpSession(session)
	assert.NoError(t, err)

	// Deactivate the session
	err = idpsession.DeactivateIdpSession("idp-deact-1")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-deact-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Should show login form since session is deactivated
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_PKCE_PlainRejected(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	// AuthPKCEEnforceSHA256 defaults to true — plain must be rejected via redirect

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz&code_challenge=abc&code_challenge_method=plain", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=invalid_request")
}

func TestHandleAuthorize_PKCE_PlainAllowed_WhenFlagDisabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthPKCEEnforceSHA256 = false
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz&code_challenge=abc&code_challenge_method=plain", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Should render login form, not an error
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_PKCE_S256Accepted(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_InvalidScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, scopes, response_types, is_active)
		VALUES ('id-scoped', 'scoped-client', 'Scoped Client', 'public', '["http://localhost/callback"]', '[]', 'openid profile', '["code"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=scoped-client&redirect_uri=http://localhost/callback&state=xyz&scope=offline_access", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Invalid scope → redirect back with error=invalid_scope
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=invalid_scope")
}

func TestHandleAuthorize_AllowedScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, scopes, response_types, is_active)
		VALUES ('id-scoped3', 'scoped-client3', 'Scoped Client 3', 'public', '["http://localhost/callback"]', '[]', 'openid profile', '["code"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=scoped-client3&redirect_uri=http://localhost/callback&state=xyz&scope=openid+profile", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_AutoLogin_NoCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Should show login form since no cookie
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_PromptNone_NoSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123&prompt=none", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// prompt=none with no session should redirect back with login_required error
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=login_required")
}

func TestHandleAuthorize_PromptNone_ValidSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES ('user-1', 'testuser', 'test@example.com', 'hashed')`)
	session := idpsession.IdpSession{ID: "idp-none-1", UserID: "user-1"}
	_ = idpsession.CreateIdpSession(session)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123&prompt=none", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-none-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// prompt=none with session should succeed and redirect with code
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "code=")
}

func TestHandleAuthorize_WithFederation(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Insert an enabled federation provider
	_, _ = db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret, enabled, sort_order)
		VALUES ('google', 'Google', 'https://accounts.google.com', 'c1', 's1', TRUE, 1)
	`)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Google")
}

func TestHandleAuthorize_PromptLogin_NoSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&prompt=login", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_MaxAge_ExceedsSession_ForcesLogin(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 24 * time.Hour
	})
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Session created 10 seconds ago
	testutils.InsertTestUser(t, "sso-user-2")
	session := idpsession.IdpSession{
		ID:     "idp-maxage-1",
		UserID: "sso-user-2",
	}
	_ = idpsession.CreateIdpSession(session)
	// Backdate created_at so that session age exceeds max_age=1
	_, _ = db.GetDB().Exec(`UPDATE idp_sessions SET created_at = datetime('now', '-10 seconds') WHERE id = ?`, "idp-maxage-1")

	// max_age=1 — session is 10s old, exceeds max_age; must force re-authentication
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=s1&max_age=1", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-maxage-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "max_age exceeded must show login form")
	assert.NotContains(t, rr.Header().Get("Location"), "code=", "must not issue auth code when max_age exceeded")
}

func TestHandleAuthorize_MaxAge_WithinSession_AutoLogins(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 24 * time.Hour
	})
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Session created 1 second ago
	testutils.InsertTestUser(t, "sso-user-3")
	session := idpsession.IdpSession{
		ID:             "idp-maxage-2",
		UserID:         "sso-user-3",
		CreatedAt:      time.Now().Add(-1 * time.Second),
		LastActivityAt: time.Now(),
	}
	_ = idpsession.CreateIdpSession(session)

	// max_age=30 — session is 1s old, within max_age; SSO auto-login should proceed
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=s1&max_age=30", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-maxage-2"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code, "within max_age must auto-login via SSO")
	assert.Contains(t, rr.Header().Get("Location"), "code=", "must issue auth code")
}

func TestHandleAuthorize_PromptLogin_BypassesSSO(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 24 * time.Hour
	})
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Create an active IdP session
	testutils.InsertTestUser(t, "sso-user-1")
	session := idpsession.IdpSession{
		ID:             "idp-login-1",
		UserID:         "sso-user-1",
		LastActivityAt: time.Now(),
	}
	_ = idpsession.CreateIdpSession(session)

	// prompt=login must force re-authentication even with an active SSO session
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=s1&prompt=login", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-login-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "prompt=login must show login form, not auto-login")
	assert.NotContains(t, rr.Header().Get("Location"), "code=", "must not issue auth code via SSO bypass")
}


// OIDC Core §3.1.2.1: prompt=consent must skip SSO auto-login and show login form
func TestHandleAuthorize_PromptConsent_BypassesSSO(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 24 * time.Hour
	})
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Create an active IdP session
	testutils.InsertTestUser(t, "sso-user-1")
	session := idpsession.IdpSession{
		ID:             "idp-consent-1",
		UserID:         "sso-user-1",
		LastActivityAt: time.Now(),
	}
	_ = idpsession.CreateIdpSession(session)

	// prompt=consent must force re-authentication even with an active SSO session
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=s1&prompt=consent", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-consent-1"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "prompt=consent must show login form, not auto-login")
	assert.NotContains(t, rr.Header().Get("Location"), "code=", "must not issue auth code via SSO bypass")
}

func TestHandleAuthorize_AllowSelfSignup(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Create account")
}

// OIDC Core §3.1.2.1: prompt=create renders the signup form directly
func TestHandleAuthorize_PromptCreate_RendersSignup(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz&prompt=create", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `name="username"`)
	assert.Contains(t, body, `name="password"`)
	assert.Contains(t, body, `name="confirm_password"`)
}

// prompt=create with self-signup disabled must show login page with error
func TestHandleAuthorize_PromptCreate_SignupDisabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = false
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz&prompt=create", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Self-registration is not enabled")
}

func TestHandleAuthorize_InvalidPrompt(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&prompt=invalid", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Should ignore invalid prompt and show login form
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
}

func TestHandleAuthorize_InvalidRedirectURI_Extra(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=none&redirect_uri=invalid", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Invalid redirect_uri — show error page
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect_uri")
}

func TestHandleAuthorize_UnknownClient_Extra(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=nonexistent&redirect_uri=http://localhost/cb", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unknown client_id")
}

func TestHandleAuthorize_UnsupportedResponseType_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=token&client_id=c1&redirect_uri=http://localhost/cb", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Invalid response_type → redirect back with error=unsupported_response_type
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=unsupported_response_type")
}

func TestHandleAuthorize_WithGenericError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=c1&redirect_uri=http://localhost/cb&error=server_error", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "server_error")
}

// TestHandleAuthorize_RequestObjectRejected verifies that a request containing
// the "request" parameter (unsigned JWT request object) is rejected with
// request_not_supported per OIDC Core §6.1.
func TestHandleAuthorize_RequestObjectRejected(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id=c1&redirect_uri=http://localhost/cb&state=xyz&request=eyJhbGciOiJub25lIn0.e30.",
		nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Must redirect back with error=request_not_supported
	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "error=request_not_supported")
	assert.Contains(t, loc, "state=xyz")
}

// TestRedirectWithError_ErrorDescriptionEncoded verifies RFC 6749 §4.1.2.1:
// error parameters MUST be added using application/x-www-form-urlencoded
// format (Appendix B), which requires percent-encoding of special characters.
func TestRedirectWithError_ErrorDescriptionEncoded(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Trigger an unsupported_response_type error — description contains spaces
	// ("response_type not allowed for this client") which MUST be percent-encoded.
	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=token&client_id=test-client&redirect_uri=http://localhost/callback&state=my+state",
		nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	require.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	require.NotEmpty(t, location)

	parsed, err := url.Parse(location)
	require.NoError(t, err)

	// RFC 6749 §4.1.2.1 + Appendix B: no raw (unencoded) spaces in the redirect URL.
	// url.Values.Encode() uses + for spaces, which is valid form-encoding.
	errDesc := parsed.Query().Get("error_description")
	assert.NotEmpty(t, errDesc, "error_description must be present")
	assert.NotContains(t, location, "error_description=response_type not allowed",
		"spaces in error_description must be encoded (as + or %%20), not passed raw")

	// State value must round-trip correctly through encoding.
	assert.Equal(t, "my state", parsed.Query().Get("state"), "state must decode back to its original value")
}
