package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/gorilla/csrf"
	"github.com/stretchr/testify/require"
)

func TestConfiguredCSRFCookieRequiredForValidSubmission(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			saved := config.Bootstrap
			t.Cleanup(func() { config.Bootstrap = saved })
			config.Bootstrap.AuthCSRFCookieName = "tenant_csrf"
			config.Bootstrap.AuthCSRFSecureCookie = secure
			config.Bootstrap.AuthCSRFProtectionSecretKey = csrfSecret
			var token string
			handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { token = csrf.Token(r); w.WriteHeader(200) }))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "/oauth2/authorize", nil))
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1)
			c := cookies[0]
			require.Equal(t, "tenant_csrf", c.Name)
			require.True(t, c.HttpOnly)
			require.Equal(t, secure, c.Secure)
			require.Empty(t, c.Domain)
			require.Equal(t, http.SameSiteLaxMode, c.SameSite)
			for _, name := range []string{"_gorilla_csrf", "tenant_csrf"} {
				r := plaintextRequest(httptest.NewRequest("POST", "/oauth2/login", nil))
				r.Header.Set("X-CSRF-Token", token)
				r.AddCookie(&http.Cookie{Name: name, Value: c.Value})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if name == "tenant_csrf" {
					require.Equal(t, 200, w.Code)
				} else {
					require.Equal(t, 403, w.Code)
				}
			}
		})
	}
}
