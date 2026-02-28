package onboarding

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleOnboard_DisabledWhenOnboarded(t *testing.T) {
	testutils.WithTestDB(t)
	_ = appsettings.SetSetting("onboarded", "true")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/onboard", nil)
	rr := httptest.NewRecorder()

	HandleOnboard(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleOnboard_DisabledWhenUsersExist(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("admin", "password", "admin@example.com")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/onboard", nil)
	rr := httptest.NewRecorder()

	HandleOnboard(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleOnboard_Get_Success(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/onboard", nil)
	rr := httptest.NewRecorder()

	HandleOnboard(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleOnboard_Post_Success(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("email", "admin@example.com")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("state", "abc123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboard(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.True(t, appsettings.IsOnboarded())

	u, err := user.UserByUsername("admin")
	assert.NoError(t, err)
	assert.Equal(t, "admin", u.Role)
}

func TestHandleOnboard_Post_PasswordMismatch(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "password123")
	form.Set("confirm_password", "wrong")
	form.Set("email", "admin@example.com")
	form.Set("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboard(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Passwords do not match")
}

func TestHandleOnboard_Post_InvalidRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("redirect_uri", "not-a-url")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboard(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleOnboard_Post_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "a") // too short
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("email", "admin@example.com")
	form.Set("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboard(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "username is invalid")
}

