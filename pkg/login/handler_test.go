package login

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

func TestHandleLoginUser(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Perform login
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect", "http://localhost/callback")
	form.Add("state", "xyz123")

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

	// Missing username (too short)
	form := url.Values{}
	form.Add("username", "ab")
	form.Add("password", "password123")
	form.Add("redirect", "http://localhost/callback")
	form.Add("state", "xyz123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleLoginUser_InvalidRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowedRedirectURIs = []string{"http://allowed.com"}
	})

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect", "http://notallowed.com/callback")
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

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "wrongpassword")
	form.Add("redirect", "http://localhost/callback")
	form.Add("state", "xyz123")

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

	form := url.Values{}
	form.Add("username", "nonexistent")
	form.Add("password", "password123")
	form.Add("redirect", "http://localhost/callback")
	form.Add("state", "xyz123")

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
		Redirect: "http://localhost/callback",
		State:    "xyz123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is invalid")
}

func TestValidateLoginRequest_InvalidRedirect(t *testing.T) {
	err := ValidateLoginRequest(LoginRequest{
		Username: "testuser",
		Password: "password123",
		Redirect: "",
		State:    "xyz123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redirect URI is invalid")
}

func TestValidateLoginRequest_MissingState(t *testing.T) {
	err := ValidateLoginRequest(LoginRequest{
		Username: "testuser",
		Password: "password123",
		Redirect: "http://localhost/callback",
		State:    "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "state is invalid")
}

func TestValidateLoginRequest_Valid(t *testing.T) {
	err := ValidateLoginRequest(LoginRequest{
		Username: "testuser",
		Password: "password123",
		Redirect: "http://localhost/callback",
		State:    "xyz123",
	})
	assert.NoError(t, err)
}

func TestHandleLoginUser_SetsIdpSessionCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Values.AuthIdpSessionCookieName = "autentico_idp_session"
		config.Values.AppOAuthPath = "/oauth2"
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect", "http://localhost/callback")
	form.Add("state", "xyz123")

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
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 0 // disabled
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect", "http://localhost/callback")
	form.Add("state", "xyz123")

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
