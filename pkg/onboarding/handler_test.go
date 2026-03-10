package onboarding

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleOnboardDirect_DisabledWhenOnboarded(t *testing.T) {
	testutils.WithTestDB(t)
	_ = appsettings.SetSetting("onboarded", "true")

	req := httptest.NewRequest(http.MethodGet, "/onboard", nil)
	rr := httptest.NewRecorder()

	HandleOnboardDirect(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/admin/", rr.Header().Get("Location"))
}

func TestHandleOnboardDirect_DisabledWhenUsersExist(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser("admin", "password", "admin@example.com")

	req := httptest.NewRequest(http.MethodGet, "/onboard", nil)
	rr := httptest.NewRecorder()

	HandleOnboardDirect(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/admin/", rr.Header().Get("Location"))
}

func TestHandleOnboardDirect_Get_Success(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/onboard", nil)
	rr := httptest.NewRecorder()

	HandleOnboardDirect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleOnboardDirect_Post_Success(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("email", "admin@example.com")

	req := httptest.NewRequest(http.MethodPost, "/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboardDirect(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/admin/", rr.Header().Get("Location"))
	assert.True(t, appsettings.IsOnboarded())

	u, err := user.UserByUsername("admin")
	assert.NoError(t, err)
	assert.Equal(t, "admin", u.Role)
}

func TestHandleOnboardDirect_Post_PasswordMismatch(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "password123")
	form.Set("confirm_password", "wrong")
	form.Set("email", "admin@example.com")

	req := httptest.NewRequest(http.MethodPost, "/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboardDirect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Passwords do not match")
}

func TestHandleOnboardDirect_Post_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("username", "a") // too short
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("email", "admin@example.com")

	req := httptest.NewRequest(http.MethodPost, "/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboardDirect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "username is invalid")
}

func TestHandleOnboardDirect_MethodNotAllowed(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodPut, "/onboard", nil)
	rr := httptest.NewRecorder()
	HandleOnboardDirect(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleOnboardDirect_Post_SsoEnabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = time.Hour
	})
	_ = appsettings.SetSetting("onboarded", "false")

	form := url.Values{}
	form.Set("username", "adminuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleOnboardDirect(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	// Verify IdP session cookie set
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "autentico_idp_session" {
			found = true
			break
		}
	}
	assert.True(t, found)
}
