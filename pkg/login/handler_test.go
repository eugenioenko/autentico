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
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestHandleLoginUser_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	// Create user and client
	_, _ = user.CreateUser("testuser", "password123", "test@example.com")
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("client_id", "test-client")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("state", "xyz")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "code=")
}

func TestHandleLoginUser_MfaTotp(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "totp"
	})

	_, _ = user.CreateUser("mfauser", "password123", "mfa@example.com")
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	form := url.Values{}
	form.Set("username", "mfauser")
	form.Set("password", "password123")
	form.Set("client_id", "test-client")
	form.Set("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
}

func TestHandleLoginUser_PasskeyOnly(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthMode = "passkey_only"
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Password login is disabled")
}

func TestHandleLoginUser_InvalidRedirect(t *testing.T) {
	testutils.WithTestDB(t)
	form := url.Values{}
	form.Set("redirect_uri", "not-a-url")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect_uri")
}

func TestHandleLoginUser_InactiveClient(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = db.GetDB().Exec(`INSERT INTO clients (id, client_id, client_name, is_active, redirect_uris) VALUES ('c1', 'inactive', 'Inc', FALSE, '["http://localhost"]')`)

	form := url.Values{}
	form.Set("client_id", "inactive")
	form.Set("redirect_uri", "http://localhost")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Client is inactive")
}

func TestHandleLoginUser_InvalidScope(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")
	form.Set("scope", "invalid")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "One or more requested scopes are not allowed")
}

func TestHandleLoginUser_LockedAccount(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("lockeduser", "password123", "l@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	// Lock the user
	_, _ = db.GetDB().Exec("UPDATE users SET locked_until = datetime('now', '+1 hour') WHERE id = ?", u.ID)

	form := url.Values{}
	form.Set("username", "lockeduser")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=Account+is+temporarily+locked")
}

func TestHandleLoginUser_EmailMfaNoSmtp(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "email"
		config.Values.SmtpHost = "" // No SMTP
	})

	_, _ = user.CreateUser("mfauseremail", "password123", "u@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "mfauseremail")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleLoginUser_InvalidCredentialsFormat(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "a") // too short
	form.Set("password", "short")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=user+credentials+error")
}

func TestHandleLoginUser_UnknownClient(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("client_id", "nonexistent")
	form.Set("redirect_uri", "http://localhost")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unknown client_id")
}

func TestHandleLoginUser_WrongPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("testuser", "correct-password", "test@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "wrong-password")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=Invalid+username+or+password")
}

func TestHandleLoginUser_NonexistentUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "nonexistent")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=Invalid+username+or+password")
}

func TestHandleLoginUser_FormParseError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader("%")) // Invalid URL encoding
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleLoginUser_SkipMfaIfTrusted(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("testuser", "password123", "test@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	
	// Enable MFA
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "totp"
		config.Values.TrustDeviceEnabled = true
	})

	// Create a trusted device
	deviceID := "trusted-1"
	_ = trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{
		ID:         deviceID,
		UserID:     u.ID,
		DeviceName: "Test",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Add trusted device cookie
	req.AddCookie(&http.Cookie{Name: trusteddevice.CookieName, Value: deviceID})
	
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Should NOT redirect to /mfa, should redirect to client with code
	assert.Contains(t, rr.Header().Get("Location"), "code=")
}

func TestHandleLoginUser_MfaMethodBoth_TotpVerified(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "password123", "mfa@test.com")
	_ = user.UpdateUser(u.ID, user.UserUpdateRequest{TotpVerified: boolPtr(true)})
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "both"
	})

	form := url.Values{}
	form.Set("username", "mfauser")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Should use TOTP
	assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
}

func TestHandleLoginUser_MfaMethodBoth_NoTotpVerified(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("mfauser", "password123", "mfa@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "both"
		config.Values.SmtpHost = "localhost" // Enable SMTP so email MFA is available
	})

	form := url.Values{}
	form.Set("username", "mfauser")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Should use Email (since method is both and user has no TOTP)
	assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
}

func TestRedirectToLogin_Extra(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppOAuthPath = "/oauth2"
	})

	req := httptest.NewRequest(http.MethodGet, "/?anything=1", nil)
	rr := httptest.NewRecorder()
	
	loginReq := LoginRequest{
		ClientID:            "c1",
		RedirectURI:         "http://cb",
		State:               "s1",
		Scope:               "openid",
		Nonce:               "n1",
		CodeChallenge:       "cc1",
		CodeChallengeMethod: "S256",
	}
	
	redirectToLogin(rr, req, loginReq, "some error")
	
	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "/oauth2/authorize")
	assert.Contains(t, loc, "error=some+error")
	assert.Contains(t, loc, "client_id=c1")
	assert.Contains(t, loc, "redirect_uri=http%3A%2F%2Fcb")
	assert.Contains(t, loc, "state=s1")
	assert.Contains(t, loc, "scope=openid")
	assert.Contains(t, loc, "nonce=n1")
	assert.Contains(t, loc, "code_challenge=cc1")
	assert.Contains(t, loc, "code_challenge_method=S256")
}

func TestHandleLoginUser_DbError_Session(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("testuser", "password123", "t@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Close DB to trigger error in DB ops
	db.CloseDB()

	HandleLoginUser(rr, req)

	// Since client lookup is first and fails if DB is closed, it returns 400
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleLoginUser_MfaEnrollment(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("enrolluser", "password123", "e@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "totp"
	})

	form := url.Values{}
	form.Set("username", "enrolluser")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Should redirect to /mfa for enrollment
	assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
}

func TestHandleLoginUser_MfaEmailEnrollment(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("enrolluser", "password123", "e@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "email"
		config.Values.SmtpHost = "localhost"
	})

	form := url.Values{}
	form.Set("username", "enrolluser")
	form.Set("password", "password123")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Should redirect to /mfa
	assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
}

func boolPtr(b bool) *bool { return &b }
