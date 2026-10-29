package passkey

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestConfiguredRegistrationCookieReadsAndClearsSameSecureName(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			withPasskeyTestDB(t)
			withPasskeyConfig(t)
			config.Bootstrap.AuthPasskeyRegistrationCookieName = "tenant_registration"
			config.Bootstrap.AuthCSRFSecureCookie = secure
			_, c, _ := beginOwnedRegistration(t, "custom-cookie-user", nil)
			name := "tenant_registration"
			if secure {
				name = "__Host-" + name
			}
			require.Equal(t, name, c.Name)
			require.Equal(t, "/", c.Path)
			require.Empty(t, c.Domain)
			require.True(t, c.HttpOnly)
			require.Equal(t, secure, c.Secure)
			require.Equal(t, http.SameSiteStrictMode, c.SameSite)
			r := httptest.NewRequest("GET", "/", nil)
			r.AddCookie(c)
			require.Equal(t, c.Value, registrationOwner(r))
			c.Name = "autentico_passkey_registration"
			if secure {
				c.Name = "__Host-" + c.Name
			}
			legacy := httptest.NewRequest("GET", "/", nil)
			legacy.AddCookie(c)
			require.Empty(t, registrationOwner(legacy))
			w := httptest.NewRecorder()
			setRegistrationCookie(w, "")
			cleared := w.Result().Cookies()
			require.Len(t, cleared, 1)
			require.Equal(t, name, cleared[0].Name)
			require.Equal(t, "/", cleared[0].Path)
			require.Empty(t, cleared[0].Domain)
			require.Empty(t, cleared[0].Value)
			require.Negative(t, cleared[0].MaxAge)
			require.Equal(t, secure, cleared[0].Secure)
		})
	}
}
