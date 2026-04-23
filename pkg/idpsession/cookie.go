package idpsession

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
)

// The IdP session cookie is scoped to Path="/" so first-party non-OAuth
// handlers (most notably /account/api/sessions) can resolve the current device
// directly from the cookie — matching Google/Auth0/Okta/Keycloak. Any legacy
// /oauth2-scoped cookie still sitting in a browser ages out naturally.
const rootCookiePath = "/"

func SetCookie(w http.ResponseWriter, sessionID string) {
	bs := config.GetBootstrap()
	http.SetCookie(w, &http.Cookie{
		Name:     bs.AuthIdpSessionCookieName,
		Value:    sessionID,
		Path:     rootCookiePath,
		HttpOnly: true,
		Secure:   bs.AuthIdpSessionSecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func ReadCookie(r *http.Request) string {
	cookie, err := r.Cookie(config.GetBootstrap().AuthIdpSessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func ClearCookie(w http.ResponseWriter) {
	bs := config.GetBootstrap()
	http.SetCookie(w, &http.Cookie{
		Name:     bs.AuthIdpSessionCookieName,
		Value:    "",
		Path:     rootCookiePath,
		HttpOnly: true,
		Secure:   bs.AuthIdpSessionSecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
