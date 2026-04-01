package passwordreset

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
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Store tests ---

func TestGenerateToken(t *testing.T) {
	raw, hash, err := generateToken()
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, raw, hash)
	// Hash should match utils.HashSHA256
	assert.Equal(t, utils.HashSHA256(raw), hash)
}

func TestCreateAndGetResetToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-user-1")

	raw, hash, err := generateToken()
	require.NoError(t, err)
	_ = raw

	expires := time.Now().Add(time.Hour)
	require.NoError(t, createResetToken("rst-user-1", hash, expires))

	userID, expiresAt, usedAt, err := getResetTokenInfo(hash)
	require.NoError(t, err)
	assert.Equal(t, "rst-user-1", userID)
	assert.WithinDuration(t, expires, expiresAt, time.Second)
	assert.Nil(t, usedAt)
}

func TestMarkTokenUsed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-user-2")

	_, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-user-2", hash, time.Now().Add(time.Hour)))

	markTokenUsed(hash)

	_, _, usedAt, err := getResetTokenInfo(hash)
	require.NoError(t, err)
	assert.NotNil(t, usedAt)
}

func TestInvalidatePreviousTokens(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-user-3")

	_, hash1, _ := generateToken()
	_, hash2, _ := generateToken()
	require.NoError(t, createResetToken("rst-user-3", hash1, time.Now().Add(time.Hour)))
	require.NoError(t, createResetToken("rst-user-3", hash2, time.Now().Add(time.Hour)))

	invalidatePreviousTokens("rst-user-3")

	_, _, usedAt1, _ := getResetTokenInfo(hash1)
	_, _, usedAt2, _ := getResetTokenInfo(hash2)
	assert.NotNil(t, usedAt1)
	assert.NotNil(t, usedAt2)
}

func TestGetResetTokenInfo_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, _, _, err := getResetTokenInfo("nonexistent-hash")
	assert.Error(t, err)
}

// --- Handler tests ---

func TestHandleForgotPassword_GET_RendersForm(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/forgot-password?client_id=test&redirect_uri=http://localhost/cb&state=s1&scope=openid", nil)
	rr := httptest.NewRecorder()

	HandleForgotPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Send reset link")
}

func TestHandleForgotPassword_POST_NoUser_ShowsSuccess(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("identifier", "nonexistent@test.com")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleForgotPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Should NOT leak that user doesn't exist — shows success message
	body := rr.Body.String()
	assert.Contains(t, body, "sent")
	assert.NotContains(t, body, "not found")
}

func TestHandleForgotPassword_POST_UserNoEmail_ShowsSuccess(t *testing.T) {
	testutils.WithTestDB(t)

	// Create user with no email
	_, err := db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password) VALUES (?, ?, '', ?)`,
		"no-email-user", "noemailuser", "hashed",
	)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("identifier", "noemailuser")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleForgotPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "sent")
}

func TestHandleForgotPassword_POST_EmptyIdentifier(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("identifier", "")
	form.Set("client_id", "test")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleForgotPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Please enter")
}

func TestHandleForgotPassword_POST_ValidUser_CreatesToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.PasswordResetExpiration = time.Hour
		// No SMTP configured, so email won't actually send (that's fine for this test)
	})

	u, err := user.CreateUser("resetme", "password123", "resetme@test.com")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("identifier", "resetme")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleForgotPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "sent")

	// Verify a token was created in the DB
	var count int
	err = db.GetDB().QueryRow(`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ?`, u.ID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestHandleResetPassword_GET_MissingToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/reset-password", nil)
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or missing")
}

func TestHandleResetPassword_GET_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/reset-password?token=bad-token", nil)
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired or has already been used")
}

func TestHandleResetPassword_GET_ExpiredToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-exp-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-exp-user", hash, time.Now().Add(-time.Hour)))

	req := httptest.NewRequest(http.MethodGet, "/oauth2/reset-password?token="+raw, nil)
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired or has already been used")
}

func TestHandleResetPassword_GET_UsedToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-used-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-used-user", hash, time.Now().Add(time.Hour)))
	markTokenUsed(hash)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/reset-password?token="+raw, nil)
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired or has already been used")
}

func TestHandleResetPassword_GET_ValidToken_ShowsForm(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-valid-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-valid-user", hash, time.Now().Add(time.Hour)))

	req := httptest.NewRequest(http.MethodGet, "/oauth2/reset-password?token="+raw, nil)
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "New Password")
	assert.Contains(t, body, "Confirm Password")
}

func TestHandleResetPassword_POST_PasswordMismatch(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-mm-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-mm-user", hash, time.Now().Add(time.Hour)))

	form := url.Values{}
	form.Set("token", raw)
	form.Set("password", "newpassword123")
	form.Set("confirm_password", "different123")
	form.Set("client_id", "test")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "do not match")
}

func TestHandleResetPassword_POST_PasswordTooShort(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinPasswordLength = 8
	})
	testutils.InsertTestUser(t, "rst-short-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-short-user", hash, time.Now().Add(time.Hour)))

	form := url.Values{}
	form.Set("token", raw)
	form.Set("password", "short")
	form.Set("confirm_password", "short")
	form.Set("client_id", "test")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "at least 8")
}

func TestHandleResetPassword_POST_ExpiredToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-exp2-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-exp2-user", hash, time.Now().Add(-time.Hour)))

	form := url.Values{}
	form.Set("token", raw)
	form.Set("password", "newpassword123")
	form.Set("confirm_password", "newpassword123")
	form.Set("client_id", "test")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired")
}

func TestHandleResetPassword_POST_AlreadyUsedToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "rst-reuse-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken("rst-reuse-user", hash, time.Now().Add(time.Hour)))
	markTokenUsed(hash)

	form := url.Values{}
	form.Set("token", raw)
	form.Set("password", "newpassword123")
	form.Set("confirm_password", "newpassword123")
	form.Set("client_id", "test")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "already been used")
}

func TestHandleResetPassword_POST_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 64
	})

	u, err := user.CreateUser("resetuser", "oldpassword123", "reset@test.com")
	require.NoError(t, err)

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken(u.ID, hash, time.Now().Add(time.Hour)))

	form := url.Values{}
	form.Set("token", raw)
	form.Set("password", "newpassword456")
	form.Set("confirm_password", "newpassword456")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "reset successfully")

	// Verify token is marked as used
	_, _, usedAt, err := getResetTokenInfo(hash)
	require.NoError(t, err)
	assert.NotNil(t, usedAt)

	// Verify old password no longer works
	_, authErr := user.AuthenticateUser("resetuser", "oldpassword123")
	assert.Error(t, authErr)

	// Verify new password works
	_, authErr = user.AuthenticateUser("resetuser", "newpassword456")
	assert.NoError(t, authErr)
}

func TestHandleResetPassword_POST_Success_InvalidatesSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 64
	})

	u, err := user.CreateUser("sessuser", "oldpass123", "sess@test.com")
	require.NoError(t, err)

	// Create a session for this user
	_, err = db.GetDB().Exec(
		`INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		 VALUES (?, ?, 'at1', 'rt1', 'agent', '127.0.0.1', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'))`,
		"sess-1", u.ID,
	)
	require.NoError(t, err)

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken(u.ID, hash, time.Now().Add(time.Hour)))

	form := url.Values{}
	form.Set("token", raw)
	form.Set("password", "newpass456")
	form.Set("confirm_password", "newpass456")
	form.Set("client_id", "test")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResetPassword(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Session should be deactivated
	var deactivatedAt *time.Time
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = ?`, "sess-1").Scan(&deactivatedAt)
	require.NoError(t, err)
	assert.NotNil(t, deactivatedAt, "session should be deactivated after password reset")
}

func TestHandleResetPassword_POST_TokenSingleUse(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 64
	})

	u, err := user.CreateUser("singleuse", "oldpass123", "single@test.com")
	require.NoError(t, err)

	raw, hash, _ := generateToken()
	require.NoError(t, createResetToken(u.ID, hash, time.Now().Add(time.Hour)))

	form := url.Values{}
	form.Set("token", raw)
	form.Set("password", "newpass456")
	form.Set("confirm_password", "newpass456")
	form.Set("client_id", "test")

	// First use — success
	req := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleResetPassword(rr, req)
	assert.Contains(t, rr.Body.String(), "reset successfully")

	// Second use — should fail
	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/reset-password", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	HandleResetPassword(rr2, req2)
	assert.Contains(t, rr2.Body.String(), "already been used")
}

func TestBuildResetURL(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		bs := config.GetBootstrap()
		bs.AppURL = "http://localhost:9999"
		bs.AppOAuthPath = "/oauth2"
	})

	params := oauthParams{
		RedirectURI: "http://localhost/cb",
		State:       "st1",
		ClientID:    "client1",
		Scope:       "openid",
	}

	result := buildResetURL("mytoken123", params)
	assert.Contains(t, result, "http://localhost:9999/oauth2/reset-password?")
	assert.Contains(t, result, "token=mytoken123")
	assert.Contains(t, result, "client_id=client1")
	assert.Contains(t, result, "state=st1")
}
