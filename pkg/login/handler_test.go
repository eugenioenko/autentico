package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/authrequest"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestAuthRequest creates an authorize request for the given client and returns its ID.
func createTestAuthRequest(t *testing.T, clientID, redirectURI string) string {
	t.Helper()
	id, err := authrequest.Create(authrequest.AuthorizeRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       "openid profile email",
		State:       "test-state",
		ResponseType: "code",
	})
	require.NoError(t, err)
	return id
}

func TestHandleLoginUser_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	_, _ = user.CreateUser("testuser", "password123", "test@example.com")
	testutils.InsertTestClient(t, "test-client", []string{"http://localhost/callback"})
	authReqID := createTestAuthRequest(t, "test-client", "http://localhost/callback")

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("auth_request_id", authReqID)

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
	authReqID := createTestAuthRequest(t, "test-client", "http://localhost/callback")

	form := url.Values{}
	form.Set("username", "mfauser")
	form.Set("password", "password123")
	form.Set("auth_request_id", authReqID)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
}

func TestHandleLoginUser_PasskeyOnly(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthMode = "passkey_only"
	})
	authReqID := createTestAuthRequest(t, "c1", "http://localhost")

	form := url.Values{}
	form.Set("auth_request_id", authReqID)
	form.Set("username", "test")
	form.Set("password", "test")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Password login is disabled")
}

func TestHandleLoginUser_MissingAuthRequestID(t *testing.T) {
	testutils.WithTestDB(t)
	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing authorization request")
}

func TestHandleLoginUser_ExpiredAuthRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	// Create an auth request with an already-expired TTL
	_, err := db.GetDB().Exec(`
		INSERT INTO authorize_requests (id, client_id, redirect_uri, scope, state, response_type, created_at, expires_at)
		VALUES ('expired-req', 'c1', 'http://localhost', 'openid', 'st', 'code', datetime('now', '-20 minutes'), datetime('now', '-10 minutes'))
	`)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("auth_request_id", "expired-req")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Authorization request expired")
}

func TestHandleLoginUser_LockedAccount(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("lockeduser", "password123", "l@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	_, _ = db.GetDB().Exec("UPDATE users SET locked_until = datetime('now', '+1 hour') WHERE id = ?", u.ID)
	authReqID := createTestAuthRequest(t, "c1", "http://localhost")

	form := url.Values{}
	form.Set("username", "lockeduser")
	form.Set("password", "password123")
	form.Set("auth_request_id", authReqID)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "Account+is+temporarily+locked")
}

func TestHandleLoginUser_EmailMfaNoSmtp(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "email"
		config.Values.SmtpHost = ""
	})

	_, _ = user.CreateUser("mfauseremail", "password123", "u@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	authReqID := createTestAuthRequest(t, "c1", "http://localhost")

	form := url.Values{}
	form.Set("username", "mfauseremail")
	form.Set("password", "password123")
	form.Set("auth_request_id", authReqID)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=")
}

func TestHandleLoginUser_InvalidCredentialsFormat(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	authReqID := createTestAuthRequest(t, "c1", "http://localhost")

	form := url.Values{}
	form.Set("username", "a") // too short
	form.Set("password", "short")
	form.Set("auth_request_id", authReqID)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=user+credentials+error")
}

func TestHandleLoginUser_InvalidAuthRequestID(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("auth_request_id", "nonexistent-id")
	form.Set("username", "testuser")
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Authorization request expired")
}

func TestHandleLoginUser_WrongPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("testuser", "correct-password", "test@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})
	authReqID := createTestAuthRequest(t, "c1", "http://localhost")

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "wrong-password")
	form.Set("auth_request_id", authReqID)

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
	authReqID := createTestAuthRequest(t, "c1", "http://localhost")

	form := url.Values{}
	form.Set("username", "nonexistent")
	form.Set("password", "password123")
	form.Set("auth_request_id", authReqID)

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

	authReqID := createTestAuthRequest(t, "c1", "http://localhost")

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("auth_request_id", authReqID)

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
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

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
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

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
	
	redirectToLogin(rr, req, "test-auth-req-id", "some error")

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "/oauth2/login")
	assert.Contains(t, loc, "auth_request_id=test-auth-req-id")
	assert.Contains(t, loc, "some+error")
}

func TestHandleLoginUser_DbError_Session(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("testuser", "password123", "t@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Close DB to trigger error in DB ops
	db.CloseDB()

	HandleLoginUser(rr, req)

	// Auth request lookup fails with closed DB → returns error page
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
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

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
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Should redirect to /mfa
	assert.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
}

func TestHandleLoginUser_UnverifiedEmail_Blocked(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireEmailVerification = true
	})

	u, _ := user.CreateUser("unverified", "password123", "unverified@test.com")
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	// Ensure user is NOT email-verified (default)
	updated, _ := user.UserByID(u.ID)
	if updated.IsEmailVerified {
		t.Fatal("user should not be email-verified at creation")
	}

	form := url.Values{}
	form.Set("username", "unverified")
	form.Set("password", "password123")
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	// Should render the "blocked" verify-email page, not redirect with code
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Header().Get("Location"), "code=")
}

func TestHandleLoginUser_AdminExemptFromEmailVerification(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireEmailVerification = true
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	// Create admin user (role = "admin")
	u, _ := user.CreateUser("adminuser", "password123", "admin@test.com")
	_, _ = db.GetDB().Exec("UPDATE users SET role = 'admin' WHERE id = ?", u.ID)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "adminuser")
	form.Set("password", "password123")
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	// Admin bypasses email verification — should get auth code
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "code=")
}

func TestHandleLoginUser_VerifiedUser_Proceeds(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireEmailVerification = true
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	u, err := user.CreateUser("verifieduser", "password123", "verified@test.com")
	require.NoError(t, err)
	require.NoError(t, user.MarkEmailVerified(u.ID))
	// Confirm the flag was actually set
	{
		updated, e := user.UserByID(u.ID)
		require.NoError(t, e)
		require.True(t, updated.IsEmailVerified, "user must be email-verified before login test")
	}
	testutils.InsertTestClient(t, "c1", []string{"http://localhost"})

	form := url.Values{}
	form.Set("username", "verifieduser")
	form.Set("password", "password123")
	form.Set("auth_request_id", createTestAuthRequest(t, "c1", "http://localhost"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "code=")
}

func boolPtr(b bool) *bool { return &b }
