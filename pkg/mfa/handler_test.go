package mfa

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestHandleMfa_MissingChallengeID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleMfa_NotFound(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=none", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code) // redirects to login
}

func TestHandleMfa_GetEnroll(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=chall1", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Setup Authenticator")
}

func TestHandleMfa_Post_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 0
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	secret, _, _ := GenerateTotpSecret("mfauser", "Auth")
	_ = user.SaveTotpSecret(u.ID, secret)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})

	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1","client_id":"c1","scope":"openid","nonce":"","code_challenge":"","code_challenge_method":""}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	now := time.Now()
	code, _ := totp.GenerateCode(secret, now)

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", code)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	testutils.AssertPostAuthInvariants(t, rr, u.ID)
}

func TestHandleMfa_Post_EnrollSuccess(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	secret, _, _ := GenerateTotpSecret("mfauser", "Auth")

	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	now := time.Now()
	code, _ := totp.GenerateCode(secret, now)

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", code)
	form.Set("totp_secret", secret)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "http://localhost/cb")

	// Verify user is now TOTP verified
	updatedUser, _ := user.UserByID(u.ID)
	assert.True(t, updatedUser.TotpVerified)
	assert.Equal(t, secret, updatedUser.TotpSecret)
}

func TestHandleMfa_Post_WrongCode(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	secret, _, _ := GenerateTotpSecret("mfauser", "Auth")
	_ = user.SaveTotpSecret(u.ID, secret)

	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", "000000") // Wrong code

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code) // Renders verify page with error
	assert.Contains(t, rr.Body.String(), "Invalid verification code")
}

func TestHandleMfa_ExpiredChallenge(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "expired",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(-time.Hour),
	}
	_ = CreateMfaChallenge(c)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=expired", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=Verification+session+has+expired")
}

func TestHandleMfa_UsedChallenge(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "used",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
		Used:       true,
	}
	_ = CreateMfaChallenge(c)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=used", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=Verification+session+has+expired")
}

func TestHandleMfa_Post_MissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader("challenge_id=1")) // missing code
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)
	// Missing code redirects back to login
	assert.Equal(t, http.StatusFound, rr.Code)
}

func TestHandleMfa_GetVerify(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	_ = user.UpdateUser(u.ID, user.UserUpdateRequest{
		TotpVerified: boolPtr(true),
	})
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=chall1", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Verification")
	assert.Contains(t, rr.Body.String(), "Enter the code from your")
}

func TestHandleMfa_Post_EmailSuccess(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "email",
		Code:       "hashed_code",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	// In handler, it checks utils.HashSHA256(code) == challenge.Code
	// Let's just use a dummy code and hash it
	_ = UpdateChallengeCode("chall1", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92")

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", "123456")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
}

func TestHandleMfa_Post_TrustDevice(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.TrustDeviceEnabled = true
		config.Values.TrustDeviceExpiration = 24 * time.Hour
	})
	u, _ := user.CreateUser("mfauser_trust", "pass", "mfa_trust@example.com")
	// Set secret and verify TOTP for standard flow
	secret, _, _ := GenerateTotpSecret("mfauser_trust", "Auth")
	_ = user.SaveTotpSecret(u.ID, secret)
	_ = user.UpdateUser(u.ID, user.UserUpdateRequest{TotpVerified: boolPtr(true)})

	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "totp",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	now := time.Now()
	code, _ := totp.GenerateCode(secret, now)

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", code)
	form.Set("trust_device", "on")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	// Verify trusted device cookie
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "autentico_trusted_device" {
			found = true
			break
		}
	}
	assert.True(t, found, "autentico_trusted_device cookie should be present")
}

func TestHandleMfa_Post_UnknownMethod(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "unknown",
		LoginState: `{}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", "123456")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	// Now redirects back to login instead of JSON 400
	assert.Equal(t, http.StatusFound, rr.Code)
}

func TestHandleMfa_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/oauth2/mfa", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleMfa_GetEmail(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "email",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	testutils.WithConfigOverride(t, func() {
		config.Values.SmtpHost = "" // SMTP not configured — should render error on the MFA page
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=chall1", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	// Now renders the verify page with an error instead of returning JSON 500
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to send verification code")
}

func TestHandleMfa_Get_UnknownMethod(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "unknown",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=chall1", nil)
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	// Implementation falls through to renderVerifyPage if method is unknown
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleMfa_Post_ChallengeNotFound(t *testing.T) {
	testutils.WithTestDB(t)
	
	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Use dummy form with nonexistent challenge
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)
	// Missing challenge_id redirects back to login
	assert.Equal(t, http.StatusFound, rr.Code)
}

func boolPtr(b bool) *bool { return &b }
