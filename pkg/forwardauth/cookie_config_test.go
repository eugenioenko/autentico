package forwardauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestConfiguredCookieFamilyAuthenticatesStripsAndClears(t *testing.T) {
	for _, origin := range []string{"https://app.other.test", "http://127.0.0.1:8888"} {
		t.Run(origin, func(t *testing.T) {
			fixture(t)
			config.Bootstrap.AuthForwardAuthCookiePrefix = "tenant_fa_"
			config.Bootstrap.AuthIdpSessionCookieName = "tenant_idp"
			config.Bootstrap.AuthRefreshTokenCookieName = "tenant_refresh"
			config.Bootstrap.AuthCSRFCookieName = "tenant_csrf"
			config.Bootstrap.AuthTrustedDeviceCookieName = "tenant_trusted"
			config.Bootstrap.AuthFederationCookieName = "tenant_federation"
			config.Bootstrap.AuthPasskeyRegistrationCookieName = "tenant_registration"
			a := crossSiteApp(t, origin)
			credential := completeLogin(t, a)
			expected := "tenant_fa_" + a.ID
			if a.secure() {
				expected = "__Host-" + expected
			}
			require.Equal(t, expected, credential.Name)
			require.Equal(t, a.secure(), credential.Secure)
			require.True(t, credential.HttpOnly)
			require.Equal(t, "/", credential.Path)
			require.Empty(t, credential.Domain)
			r := req(a, "/check")
			r.AddCookie(credential)
			for _, name := range []string{"tenant_idp", "tenant_refresh", "tenant_csrf", "tenant_trusted", "__Host-tenant_federation", "__Host-tenant_registration", "tenant_fa_other", "__Host-tenant_fa_other_flow_state", "autentico_fa_old", "__Host-autentico_fa_old_flow_state", "autentico_idp_session", "autentico_refresh_token", "_gorilla_csrf", "autentico_trusted_device", "__Host-autentico_federation", "__Host-autentico_passkey_registration"} {
				r.AddCookie(&http.Cookie{Name: name, Value: "withheld-secret"})
			}
			r.AddCookie(&http.Cookie{Name: "app-preference", Value: "dark"})
			w := httptest.NewRecorder()
			HandleCheck(w, r)
			require.Equal(t, 204, w.Code)
			require.Equal(t, "app-preference=dark", w.Header().Get("Cookie"))
			legacy := *credential
			legacy.Name = "autentico_fa_" + a.ID
			if a.secure() {
				legacy.Name = "__Host-" + legacy.Name
			}
			require.Equal(t, 401, checked(t, a, &legacy).Code)
			logout := req(a, a.route("logout"))
			logout.Method = "POST"
			logout.Header.Set("Origin", a.Origin)
			logout.AddCookie(credential)
			cleared := httptest.NewRecorder()
			HandleLogout(cleared, logout)
			require.Equal(t, 204, cleared.Code)
			cookies := cleared.Result().Cookies()
			require.Len(t, cookies, 1)
			require.Equal(t, expected, cookies[0].Name)
			require.Negative(t, cookies[0].MaxAge)
			require.Equal(t, a.secure(), cookies[0].Secure)
			require.Equal(t, "/", cookies[0].Path)
			require.Empty(t, cookies[0].Domain)
			require.Equal(t, 401, checked(t, a, credential).Code)
		})
	}
}
