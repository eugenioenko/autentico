package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
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

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleAuthorize_InvalidResponseType(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=token&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleAuthorize_InvalidRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=not-a-valid-uri&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleAuthorize_RedirectURIInvalid(t *testing.T) {
	testutils.WithTestDB(t)

	// A URI with no host is syntactically invalid
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=not-a-valid-uri&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleAuthorize_InactiveClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert an inactive client
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, is_active)
		VALUES ('id-1', 'inactive-client', 'Test Client', 'public', '["http://localhost/callback"]', FALSE)
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
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, is_active)
		VALUES ('id-2', 'strict-client', 'Test Client', 'confidential', '["http://allowed.com/callback"]', TRUE)
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
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, response_types, is_active)
		VALUES ('id-3', 'token-only-client', 'Test Client', 'public', '["http://localhost/callback"]', '["token"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=token-only-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Response type not allowed for this client")
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

	// Should show login form since session idle time exceeded
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
	assert.Contains(t, rr.Body.String(), "username")
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
	assert.Contains(t, rr.Body.String(), "username")
}

func TestHandleAuthorize_PKCE_PlainRejected(t *testing.T) {
	testutils.WithTestDB(t)
	// AuthPKCEEnforceSHA256 defaults to true — plain must be rejected

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz&code_challenge=abc&code_challenge_method=plain", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
	assert.Contains(t, rr.Body.String(), "plain")
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
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, response_types, is_active)
		VALUES ('id-scoped', 'scoped-client', 'Scoped Client', 'public', '["http://localhost/callback"]', 'openid profile', '["code"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=scoped-client&redirect_uri=http://localhost/callback&state=xyz&scope=offline_access", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "not allowed")
}

func TestHandleAuthorize_PartiallyInvalidScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, response_types, is_active)
		VALUES ('id-scoped2', 'scoped-client2', 'Scoped Client 2', 'public', '["http://localhost/callback"]', 'openid profile', '["code"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=scoped-client2&redirect_uri=http://localhost/callback&state=xyz&scope=openid+offline_access", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "not allowed")
}

func TestHandleAuthorize_AllowedScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, response_types, is_active)
		VALUES ('id-scoped3', 'scoped-client3', 'Scoped Client 3', 'public', '["http://localhost/callback"]', 'openid profile', '["code"]', TRUE)
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
	assert.Contains(t, rr.Body.String(), "username")
}
