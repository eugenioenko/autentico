package trusteddevice

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestConfiguredCookieRetainsDeviceBindingAndAttributes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run("secure="+map[bool]string{false: "false", true: "true"}[secure], func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Bootstrap.AuthTrustedDeviceCookieName = "tenant_trusted"
				config.Bootstrap.AuthIdpSessionSecureCookie = secure
				config.Bootstrap.AppOAuthPath = "/auth"
			})
			testutils.InsertTestUser(t, "cookie-owner")
			require.NoError(t, CreateTrustedDevice(sampleDevice("custom-device", "cookie-owner"), "device-secret"))
			w := httptest.NewRecorder()
			SetCookie(w, "device-secret", 24*time.Hour)
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1)
			c := cookies[0]
			require.Equal(t, "tenant_trusted", c.Name)
			require.Equal(t, "/auth", c.Path)
			require.Empty(t, c.Domain)
			require.True(t, c.HttpOnly)
			require.Equal(t, secure, c.Secure)
			require.Equal(t, http.SameSiteStrictMode, c.SameSite)
			require.Equal(t, 86400, c.MaxAge)
			r := httptest.NewRequest("GET", "/auth/authorize", nil)
			r.AddCookie(c)
			require.True(t, IsDeviceTrusted("cookie-owner", r))
			require.False(t, IsDeviceTrusted("another-user", r))
			legacy := httptest.NewRequest("GET", "/auth/authorize", nil)
			legacy.AddCookie(&http.Cookie{Name: CookieName, Value: c.Value})
			require.Empty(t, ReadCookie(legacy))
			require.False(t, IsDeviceTrusted("cookie-owner", legacy))
		})
	}
}
