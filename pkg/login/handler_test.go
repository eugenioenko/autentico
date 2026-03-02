package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleLoginUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Create a test user
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Perform login
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "http://localhost/callback")
	assert.Contains(t, rr.Header().Get("Location"), "code=")
	assert.Contains(t, rr.Header().Get("Location"), "state=xyz123")
}

func TestHandleLoginUser_NonPostMethod(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/login", nil)
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Only POST method is allowed")
}

func TestHandleLoginUser_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	// Username too short (min is 4)
	form := url.Values{}
	form.Add("username", "ab")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	// Validation errors redirect back to the login form instead of returning JSON
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/oauth2/authorize")
	assert.Contains(t, rr.Header().Get("Location"), "error=")
}

func TestHandleLoginUser_InvalidRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "not-a-valid-uri") // syntactically invalid (no scheme/host)
	form.Add("state", "xyz123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect_uri")
}

func TestHandleLoginUser_WrongCredentials(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "wrongpassword")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	assert.Contains(t, location, "/oauth2/authorize")
	assert.Contains(t, location, "error=")
}

func TestHandleLoginUser_NonExistentUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	form := url.Values{}
	form.Add("username", "nonexistent")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	assert.Contains(t, location, "/oauth2/authorize")
	assert.Contains(t, location, "error=")
}

func TestValidateLoginRequest_InvalidPassword(t *testing.T) {
	err := ValidateLoginRequest(LoginRequest{
		Username: "testuser",
		Password: "ab",
		RedirectURI: "http://localhost/callback",
		State:    "xyz123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is invalid")
}

func TestValidateLoginRequest_InvalidRedirect(t *testing.T) {
	err := ValidateLoginRequest(LoginRequest{
		Username: "testuser",
		Password: "password123",
		RedirectURI: "",
		State:    "xyz123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redirect URI is invalid")
}

func TestValidateLoginRequest_MissingState(t *testing.T) {
	// state is optional per OAuth2 spec (RECOMMENDED but not REQUIRED)
	err := ValidateLoginRequest(LoginRequest{
		Username: "testuser",
		Password: "password123",
		RedirectURI: "http://localhost/callback",
		State:    "",
	})
	assert.NoError(t, err)
}

func TestValidateLoginRequest_Valid(t *testing.T) {
	err := ValidateLoginRequest(LoginRequest{
		Username: "testuser",
		Password: "password123",
		RedirectURI: "http://localhost/callback",
		State:    "xyz123",
	})
	assert.NoError(t, err)
}

func TestHandleLoginUser_SetsIdpSessionCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
		config.Bootstrap.AppOAuthPath = "/oauth2"
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	// Verify IdP session cookie is set
	cookies := rr.Result().Cookies()
	var idpCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "autentico_idp_session" {
			idpCookie = c
			break
		}
	}
	assert.NotNil(t, idpCookie, "IdP session cookie should be set")
	assert.True(t, idpCookie.HttpOnly, "Cookie should be HttpOnly")
	assert.Equal(t, http.SameSiteStrictMode, idpCookie.SameSite, "Cookie should be SameSite=Strict")
	assert.NotEmpty(t, idpCookie.Value, "Cookie value should not be empty")
}

func TestHandleLoginUser_NoIdpCookieWhenDisabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 0 // disabled
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	// Verify NO IdP session cookie is set
	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		assert.NotEqual(t, "autentico_idp_session", c.Name, "IdP session cookie should NOT be set when disabled")
	}
}

func TestHandleLoginUser_MfaRedirect(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.MfaEnabled = true
		config.Values.MfaMethod = "totp"
		config.Values.AuthMode = "password"
		config.Bootstrap.AppOAuthPath = "/oauth2"

		_, _ = user.CreateUser("mfauser", "password123", "mfa@example.com")

		form := url.Values{}
		form.Set("username", "mfauser")
		form.Set("password", "password123")
		form.Set("redirect_uri", "http://localhost/callback")
		form.Set("state", "xyz")
		form.Set("client_id", "test-client")

		req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		HandleLoginUser(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
	})
}

func TestHandleLoginUser_UnknownClientID(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "nonexistent-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unknown client_id")
}

func TestHandleLoginUser_InactiveClient(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, is_active)
		VALUES ('id-inactive', 'inactive-client', 'Inactive Client', 'public', '["http://localhost/callback"]', FALSE)
	`)
	require.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "inactive-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Client is inactive")
}

func TestHandleLoginUser_InvalidScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, is_active)
		VALUES ('id-scoped', 'scoped-client', 'Scoped Client', 'public', '["http://localhost/callback"]', 'openid profile', TRUE)
	`)
	require.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "scoped-client")
	form.Add("scope", "offline_access") // not allowed for this client

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_scope")
}

func TestHandleLoginUser_PartiallyInvalidScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, is_active)
		VALUES ('id-scoped2', 'scoped-client2', 'Scoped Client 2', 'public', '["http://localhost/callback"]', 'openid profile', TRUE)
	`)
	require.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "scoped-client2")
	form.Add("scope", "openid offline_access") // "openid" is allowed, but "offline_access" is not

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_scope")
}

func TestHandleLoginUser_AllowedScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, is_active)
		VALUES ('id-scoped3', 'scoped-client3', 'Scoped Client 3', 'public', '["http://localhost/callback"]', 'openid profile', TRUE)
	`)
	require.NoError(t, err)

	_, err = user.CreateUser("testuser", "password123", "testuser@example.com")
	require.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "scoped-client3")
	form.Add("scope", "openid profile") // both scopes are allowed

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "code=")
}

func TestHandleLoginUser_RedirectURINotAllowedForClient(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "strict-client", []string{"http://allowed.example.com/callback"})

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect_uri", "http://evil.example.com/callback")
	form.Add("state", "xyz123")
	form.Add("client_id", "strict-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Redirect URI not allowed for this client")
}

