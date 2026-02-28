package idpsession

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
)

func SetCookie(w http.ResponseWriter, sessionID string) {
	bs := config.GetBootstrap()
	http.SetCookie(w, &http.Cookie{
		Name:     bs.AuthIdpSessionCookieName,
		Value:    sessionID,
		Path:     bs.AppOAuthPath,
		HttpOnly: true,
		Secure:   bs.AuthIdpSessionSecureCookie,
		SameSite: http.SameSiteStrictMode,
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
		Path:     bs.AppOAuthPath,
		HttpOnly: true,
		Secure:   bs.AuthIdpSessionSecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
