package idpsession

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
)

func SetCookie(w http.ResponseWriter, sessionID string) {
	cfg := config.Get()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.AuthIdpSessionCookieName,
		Value:    sessionID,
		Path:     cfg.AppOAuthPath,
		HttpOnly: true,
		Secure:   cfg.AuthIdpSessionSecureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

func ReadCookie(r *http.Request) string {
	cfg := config.Get()
	cookie, err := r.Cookie(cfg.AuthIdpSessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func ClearCookie(w http.ResponseWriter) {
	cfg := config.Get()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.AuthIdpSessionCookieName,
		Value:    "",
		Path:     cfg.AppOAuthPath,
		HttpOnly: true,
		Secure:   cfg.AuthIdpSessionSecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
