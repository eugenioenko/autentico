package idpsession

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestSetCookie(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
		config.Bootstrap.AppOAuthPath = "/oauth2"
		config.Bootstrap.AuthIdpSessionSecureCookie = false
	})

	rr := httptest.NewRecorder()
	SetCookie(rr, "test-session-id")

	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.Equal(t, "autentico_idp_session", cookie.Name)
	assert.Equal(t, "test-session-id", cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
}

func TestReadCookie(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "my-session-id"})

	result := ReadCookie(req)
	assert.Equal(t, "my-session-id", result)
}

func TestReadCookie_Missing(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	result := ReadCookie(req)
	assert.Empty(t, result)
}

func TestClearCookie(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
		config.Bootstrap.AppOAuthPath = "/oauth2"
		config.Bootstrap.AuthIdpSessionSecureCookie = false
	})

	rr := httptest.NewRecorder()
	ClearCookie(rr)

	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.Equal(t, "autentico_idp_session", cookie.Name)
	assert.Equal(t, "", cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, -1, cookie.MaxAge)
}
