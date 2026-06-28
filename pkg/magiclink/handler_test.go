package magiclink

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/authzsig"
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
	assert.Equal(t, utils.HashSHA256(raw), hash)
}

func TestCreateAndGetMagicLinkToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "ml-user-1")

	raw, hash, err := generateToken()
	require.NoError(t, err)
	_ = raw

	expires := time.Now().Add(time.Hour)
	require.NoError(t, createMagicLinkToken("ml-user-1", hash, "", expires))

	userID, expiresAt, usedAt, err := getMagicLinkTokenInfo(hash)
	require.NoError(t, err)
	assert.Equal(t, "ml-user-1", userID)
	assert.WithinDuration(t, expires, expiresAt, time.Second)
	assert.Nil(t, usedAt)
}

func TestMarkMagicLinkTokenUsed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "ml-user-2")

	_, hash, _ := generateToken()
	require.NoError(t, createMagicLinkToken("ml-user-2", hash, "", time.Now().Add(time.Hour)))

	markTokenUsed(hash)

	_, _, usedAt, err := getMagicLinkTokenInfo(hash)
	require.NoError(t, err)
	assert.NotNil(t, usedAt)
}

func TestInvalidatePreviousMagicLinkTokens(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "ml-user-3")

	_, hash1, _ := generateToken()
	_, hash2, _ := generateToken()
	require.NoError(t, createMagicLinkToken("ml-user-3", hash1, "", time.Now().Add(time.Hour)))
	require.NoError(t, createMagicLinkToken("ml-user-3", hash2, "", time.Now().Add(time.Hour)))

	invalidatePreviousTokens("ml-user-3")

	_, _, usedAt1, _ := getMagicLinkTokenInfo(hash1)
	_, _, usedAt2, _ := getMagicLinkTokenInfo(hash2)
	assert.NotNil(t, usedAt1)
	assert.NotNil(t, usedAt2)
}

func TestGetMagicLinkTokenInfo_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, _, _, err := getMagicLinkTokenInfo("nonexistent-hash")
	assert.Error(t, err)
}

// --- Handler tests ---

func TestHandleMagicLink_GET_RendersForm(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.SmtpHost = "smtp.test.com"
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link?client_id=test&redirect_uri=http://localhost/cb&state=s1&scope=openid", nil)
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "发送登录链接")
}

func TestHandleMagicLink_GET_Disabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = false
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link?client_id=test&redirect_uri=http://localhost/cb&state=s1&scope=openid", nil)
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "not enabled")
}

func TestHandleMagicLink_GET_NoSmtp(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.SmtpHost = ""
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link?client_id=test&redirect_uri=http://localhost/cb&state=s1&scope=openid", nil)
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "not configured")
}

func TestHandleMagicLink_POST_EmptyEmail(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.SmtpHost = "smtp.test.com"
	})

	form := url.Values{}
	form.Set("email", "")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	testutils.SetAuthorizeSig(form)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Please enter")
}

func TestHandleMagicLink_POST_NoUser_ShowsSuccess(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.SmtpHost = "smtp.test.com"
	})

	form := url.Values{}
	form.Set("email", "nonexistent@test.com")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	testutils.SetAuthorizeSig(form)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "我们已发送")
	assert.NotContains(t, body, "not found")
}

func TestHandleMagicLink_POST_ValidUser_CreatesToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.MagicLinkExpiration = 15 * time.Minute
		config.Values.SmtpHost = "smtp.test.com"
	})

	u, err := user.CreateUser("mluser", "password123", "mluser@test.com")
	require.NoError(t, err)
	require.NoError(t, user.MarkEmailVerified(u.ID))

	form := url.Values{}
	form.Set("email", "mluser@test.com")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	testutils.SetAuthorizeSig(form)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "我们已发送")

	var count int
	err = db.GetDB().QueryRow(`SELECT COUNT(*) FROM magic_link_tokens WHERE user_id = ?`, u.ID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestHandleMagicLink_POST_UnverifiedEmail_NoTokenCreated(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.SmtpHost = "smtp.test.com"
	})

	u, err := user.CreateUser("unverified-ml", "password123", "unverified-ml@test.com")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("email", "unverified-ml@test.com")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	testutils.SetAuthorizeSig(form)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "我们已发送")

	var count int
	err = db.GetDB().QueryRow(`SELECT COUNT(*) FROM magic_link_tokens WHERE user_id = ?`, u.ID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "no token should be created for unverified email")
}

func TestHandleMagicLink_POST_InvalidSig_RejectsRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.SmtpHost = "smtp.test.com"
	})

	form := url.Values{}
	form.Set("email", "test@test.com")
	form.Set("client_id", "test")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	form.Set("authorize_sig", "tampered-signature")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLink(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "tampered")
}

// --- Verify handler tests ---

func TestHandleMagicLinkVerify_MissingToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify", nil)
	rr := httptest.NewRecorder()

	HandleMagicLinkVerify(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or missing")
}

func TestHandleMagicLinkVerify_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?token=bad-token", nil)
	rr := httptest.NewRecorder()

	HandleMagicLinkVerify(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "无效或已被使用")
}

func TestHandleMagicLinkVerify_ExpiredToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
	})
	testutils.InsertTestUser(t, "ml-exp-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createMagicLinkToken("ml-exp-user", hash, "", time.Now().Add(-time.Hour)))

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?token="+raw, nil)
	rr := httptest.NewRecorder()

	HandleMagicLinkVerify(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired")
}

func TestHandleMagicLinkVerify_UsedToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
	})
	testutils.InsertTestUser(t, "ml-used-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createMagicLinkToken("ml-used-user", hash, "", time.Now().Add(time.Hour)))
	markTokenUsed(hash)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?token="+raw, nil)
	rr := httptest.NewRecorder()

	HandleMagicLinkVerify(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "already been used")
}

func TestHandleMagicLinkVerify_Disabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = false
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?token=sometoken", nil)
	rr := httptest.NewRecorder()

	HandleMagicLinkVerify(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "not enabled")
}

func TestHandleMagicLinkVerify_ValidToken_RedirectsWithCode(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute
	})

	testutils.InsertTestClient(t, "ml-client", []string{"http://localhost:3000/callback"})
	u, err := user.CreateUser("ml-verify-user", "password123", "ml-verify@test.com")
	require.NoError(t, err)
	require.NoError(t, user.MarkEmailVerified(u.ID))

	raw, hash, _ := generateToken()
	require.NoError(t, createMagicLinkToken(u.ID, hash, "", time.Now().Add(time.Hour)))

	q := url.Values{}
	q.Set("token", raw)
	q.Set("client_id", "ml-client")
	q.Set("redirect_uri", "http://localhost:3000/callback")
	q.Set("state", "teststate")
	q.Set("scope", "openid")
	testutils.SetAuthorizeSig(q)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	HandleMagicLinkVerify(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "http://localhost:3000/callback")
	assert.Contains(t, loc, "code=")
	assert.Contains(t, loc, "state=teststate")
}

func TestHandleMagicLinkVerify_TokenSingleUse(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute
	})

	testutils.InsertTestClient(t, "ml-client-su", []string{"http://localhost:3000/callback"})
	u, err := user.CreateUser("ml-su-user", "password123", "ml-su@test.com")
	require.NoError(t, err)
	require.NoError(t, user.MarkEmailVerified(u.ID))

	raw, hash, _ := generateToken()
	require.NoError(t, createMagicLinkToken(u.ID, hash, "", time.Now().Add(time.Hour)))

	q := url.Values{}
	q.Set("token", raw)
	q.Set("client_id", "ml-client-su")
	q.Set("redirect_uri", "http://localhost:3000/callback")
	q.Set("state", "s1")
	q.Set("scope", "openid")
	testutils.SetAuthorizeSig(q)

	// First use — success (redirect with code)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	HandleMagicLinkVerify(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "code=")

	// Second use — should fail
	req2 := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?"+q.Encode(), nil)
	rr2 := httptest.NewRecorder()
	HandleMagicLinkVerify(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "already been used")
}

func TestHandleMagicLinkVerify_InvalidSig_RejectsRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
	})
	testutils.InsertTestUser(t, "ml-sig-user")

	raw, hash, _ := generateToken()
	require.NoError(t, createMagicLinkToken("ml-sig-user", hash, "", time.Now().Add(time.Hour)))

	q := url.Values{}
	q.Set("token", raw)
	q.Set("client_id", "test")
	q.Set("redirect_uri", "http://localhost/cb")
	q.Set("state", "s1")
	q.Set("scope", "openid")
	q.Set("authorize_sig", "tampered-signature")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?"+q.Encode(), nil)
	rr := httptest.NewRecorder()

	HandleMagicLinkVerify(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "tampered")
}

// --- Code verify handler tests ---

func TestHandleMagicLinkVerifyCode_NoEmail_Rejected(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute
	})

	testutils.InsertTestClient(t, "ml-code-client", []string{"http://localhost:3000/callback"})
	u, err := user.CreateUser("ml-code-user", "password123", "ml-code@test.com")
	require.NoError(t, err)
	require.NoError(t, user.MarkEmailVerified(u.ID))

	code := "123456"
	codeHash := utils.HashSHA256(code)
	_, tokenHash, _ := generateToken()
	require.NoError(t, createMagicLinkToken(u.ID, tokenHash, codeHash, time.Now().Add(time.Hour)))

	// Submit code WITHOUT email — should fail with generic error
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", "ml-code-client")
	form.Set("redirect_uri", "http://localhost:3000/callback")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	testutils.SetAuthorizeSig(form)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLinkVerifyCode(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid code")
}

func TestHandleMagicLinkVerifyCode_WrongEmail_Rejected(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute
	})

	testutils.InsertTestClient(t, "ml-code-client2", []string{"http://localhost:3000/callback"})
	u, err := user.CreateUser("ml-code-user2", "password123", "ml-code2@test.com")
	require.NoError(t, err)
	require.NoError(t, user.MarkEmailVerified(u.ID))

	code := "654321"
	codeHash := utils.HashSHA256(code)
	_, tokenHash, _ := generateToken()
	require.NoError(t, createMagicLinkToken(u.ID, tokenHash, codeHash, time.Now().Add(time.Hour)))

	// Submit correct code but wrong email — should fail with same generic error
	form := url.Values{}
	form.Set("code", code)
	form.Set("email", "attacker@evil.com")
	form.Set("client_id", "ml-code-client2")
	form.Set("redirect_uri", "http://localhost:3000/callback")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	testutils.SetAuthorizeSig(form)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLinkVerifyCode(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid code")
}

func TestHandleMagicLinkVerifyCode_CorrectEmailAndCode_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute
	})

	testutils.InsertTestClient(t, "ml-code-client3", []string{"http://localhost:3000/callback"})
	u, err := user.CreateUser("ml-code-user3", "password123", "ml-code3@test.com")
	require.NoError(t, err)
	require.NoError(t, user.MarkEmailVerified(u.ID))

	code := "987654"
	codeHash := utils.HashSHA256(code)
	_, tokenHash, _ := generateToken()
	require.NoError(t, createMagicLinkToken(u.ID, tokenHash, codeHash, time.Now().Add(time.Hour)))

	form := url.Values{}
	form.Set("code", code)
	form.Set("email", "ml-code3@test.com")
	form.Set("client_id", "ml-code-client3")
	form.Set("redirect_uri", "http://localhost:3000/callback")
	form.Set("state", "s1")
	form.Set("scope", "openid")
	testutils.SetAuthorizeSig(form)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleMagicLinkVerifyCode(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "http://localhost:3000/callback")
	assert.Contains(t, loc, "code=")
}

func TestBuildMagicLinkURL(t *testing.T) {
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

	sig := authzsig.Sign(authzsig.AuthorizeParams{
		ClientID:    "client1",
		RedirectURI: "http://localhost/cb",
		Scope:       "openid",
		State:       "st1",
	})

	result := buildMagicLinkURL("mytoken123", params, sig)
	assert.Contains(t, result, "http://localhost:9999/oauth2/magic-link/verify?")
	assert.Contains(t, result, "token=mytoken123")
	assert.Contains(t, result, "client_id=client1")
	assert.Contains(t, result, "state=st1")
	assert.Contains(t, result, "authorize_sig=")
}
