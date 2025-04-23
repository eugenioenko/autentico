package middleware

import (
	"autentico/pkg/config"

	"github.com/gorilla/csrf"
)

var CSRFMiddleware = csrf.Protect(
	[]byte(config.Get().AuthCSRFProtectionSecretKey),
	csrf.Secure(config.Get().AuthCSRFSecureCookie),
	csrf.TrustedOrigins([]string{config.Get().AppHost}),
)
