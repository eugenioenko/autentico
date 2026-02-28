package middleware

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/gorilla/csrf"
)

func CSRFMiddleware(next http.Handler) http.Handler {
	bs := config.GetBootstrap()
	return csrf.Protect(
		[]byte(bs.AuthCSRFProtectionSecretKey),
		csrf.Secure(bs.AuthCSRFSecureCookie),
		csrf.TrustedOrigins([]string{bs.AppHost}),
	)(next)
}
