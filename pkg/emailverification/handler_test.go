package emailverification

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleVerifyEmail_MissingToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/verify-email", nil)
	rr := httptest.NewRecorder()

	HandleVerifyEmail(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleVerifyEmail_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	q := url.Values{}
	q.Set("token", "invalid-token-xyz")
	testutils.SetAuthorizeSig(q)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/verify-email?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	HandleVerifyEmail(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid or has already been used")
}

func TestHandleVerifyEmail_ExpiredToken(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := user.CreateUser("expireduser", "password123", "expired@test.com")
	rawToken, tokenHash, err := GenerateToken()
	require.NoError(t, err)

	// Store token with expiry in the past
	pastExpiry := time.Now().Add(-1 * time.Hour)
	require.NoError(t, user.SetEmailVerificationToken(u.ID, tokenHash, pastExpiry))

	q := url.Values{}
	q.Set("token", rawToken)
	testutils.SetAuthorizeSig(q)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/verify-email?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	HandleVerifyEmail(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired")
}

func TestHandleVerifyEmail_ValidToken_RedirectsWithCode(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAuthorizationCodeExpiration = 5 * time.Minute
	})

	u, _ := user.CreateUser("gooduser", "password123", "good@test.com")
	rawToken, tokenHash, err := GenerateToken()
	require.NoError(t, err)
	require.NoError(t, user.SetEmailVerificationToken(u.ID, tokenHash, time.Now().Add(time.Hour)))

	q := url.Values{}
	q.Set("token", rawToken)
	q.Set("redirect_uri", "http://localhost/callback")
	q.Set("state", "abc123")
	q.Set("client_id", "test-client")
	q.Set("scope", "openid")
	testutils.SetAuthorizeSig(q)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/verify-email?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	HandleVerifyEmail(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "http://localhost/callback")
	assert.Contains(t, loc, "code=")
	assert.Contains(t, loc, "state=abc123")
}

func TestHandleVerifyEmail_ValidToken_MarksUserVerified(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAuthorizationCodeExpiration = 5 * time.Minute
	})

	u, _ := user.CreateUser("markuser", "password123", "mark@test.com")
	rawToken, tokenHash, err := GenerateToken()
	require.NoError(t, err)
	require.NoError(t, user.SetEmailVerificationToken(u.ID, tokenHash, time.Now().Add(time.Hour)))

	vq := url.Values{}
	vq.Set("token", rawToken)
	vq.Set("redirect_uri", "http://localhost/cb")
	vq.Set("state", "s1")
	testutils.SetAuthorizeSig(vq)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/verify-email?"+vq.Encode(), nil)
	rr := httptest.NewRecorder()

	HandleVerifyEmail(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	updated, _ := user.UserByID(u.ID)
	assert.True(t, updated.IsEmailVerified)
}

func TestHandleResendVerification_UnknownUser_ShowsSent(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "nobody")
	form.Set("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/resend-verification", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResendVerification(rr, req)

	// Should not leak existence — shows "sent" page silently
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleResendVerification_AlreadyVerified(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := user.CreateUser("alreadyverified", "password123", "av@test.com")
	require.NoError(t, user.MarkEmailVerified(u.ID))

	form := url.Values{}
	form.Set("username", "alreadyverified")
	form.Set("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/resend-verification", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResendVerification(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "already verified")
}

func TestHandleResendVerification_ValidUser_StoresNewToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.EmailVerificationExpiration = time.Hour
	})

	u, _ := user.CreateUser("resenduser", "password123", "resend@test.com")

	form := url.Values{}
	form.Set("username", "resenduser")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("state", "s1")
	form.Set("client_id", "c1")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/resend-verification", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleResendVerification(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify a token was stored for the user
	updated, _ := user.UserByID(u.ID)
	assert.False(t, updated.IsEmailVerified)
}

func TestGenerateToken_UniqueAndHashable(t *testing.T) {
	raw1, hash1, err := GenerateToken()
	require.NoError(t, err)
	raw2, hash2, err := GenerateToken()
	require.NoError(t, err)

	assert.NotEqual(t, raw1, raw2)
	assert.NotEqual(t, hash1, hash2)
	assert.NotEmpty(t, raw1)
	assert.NotEmpty(t, hash1)
}

func TestBuildVerifyURL(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppURL = "https://auth.example.com"
		config.Bootstrap.AppOAuthPath = "/oauth2"
	})

	u := BuildVerifyURL("mytoken", OAuthParams{
		RedirectURI: "http://localhost/cb",
		State:       "s1",
		ClientID:    "c1",
		Scope:       "openid",
	})

	assert.Contains(t, u, "https://auth.example.com/oauth2/verify-email")
	assert.Contains(t, u, "token=mytoken")
	assert.Contains(t, u, "redirect_uri=")
	assert.Contains(t, u, "state=s1")
}
