package signup

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
)

func TestHandleSignup_DisabledReturns404(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = false
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/signup", nil)
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleSignup_WrongMethod(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	req := httptest.NewRequest(http.MethodPut, "/oauth2/signup", nil)
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleSignup_Post_InvalidRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect", "not-a-valid-uri") // syntactically invalid
	form.Set("state", "xyz123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect_uri")
}

func TestHandleSignup_Post_PasswordMismatch(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "different456")
	form.Set("redirect", "http://localhost/callback")
	form.Set("state", "xyz123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Passwords do not match")
}

func TestHandleSignup_Post_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ValidationMinUsernameLength = 4
	})

	form := url.Values{}
	form.Set("username", "ab") // too short
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect", "http://localhost/callback")
	form.Set("state", "xyz123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "username is invalid")
}

func TestHandleSignup_Post_DuplicateUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ValidationUsernameIsEmail = false
	})

	_, err := user.CreateUser("existinguser", "password123", "existing@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Set("username", "existinguser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect", "http://localhost/callback")
	form.Set("state", "xyz123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Could not create account")
}

func TestHandleSignup_Post_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ValidationUsernameIsEmail = false
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect", "http://localhost/callback")
	form.Set("state", "abc123")
	form.Set("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	assert.Contains(t, location, "http://localhost/callback")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "state=abc123")
}

func TestHandleSignup_Post_SetsIdpSessionCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ValidationUsernameIsEmail = false
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect", "http://localhost/callback")
	form.Set("state", "abc123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	cookies := rr.Result().Cookies()
	var idpCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "autentico_idp_session" {
			idpCookie = c
			break
		}
	}
	assert.NotNil(t, idpCookie, "IdP session cookie should be set after signup")
	assert.NotEmpty(t, idpCookie.Value)
	assert.True(t, idpCookie.HttpOnly)
}

func TestHandleSignup_Post_NoIdpCookieWhenDisabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ValidationUsernameIsEmail = false
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect", "http://localhost/callback")
	form.Set("state", "abc123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	for _, c := range rr.Result().Cookies() {
		assert.NotEqual(t, "autentico_idp_session", c.Name, "IdP cookie should NOT be set when SSO is disabled")
	}
}
