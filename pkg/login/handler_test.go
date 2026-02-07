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
