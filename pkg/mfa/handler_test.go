package mfa

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

	code, _ := totp.GenerateCode(secret, time.Now())

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", code)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "http://localhost/cb")
}

func TestGenerateEmailOTP(t *testing.T) {
	otp, err := GenerateEmailOTP()
	assert.NoError(t, err)
	assert.Len(t, otp, 6)
}
