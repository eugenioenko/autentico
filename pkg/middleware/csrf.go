package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/gorilla/csrf"
)

func csrfErrorHandler(w http.ResponseWriter, r *http.Request) {
	reason := csrf.FailureReason(r)
	requestID := GetRequestID(r.Context())

	hint := ""
	bs := config.GetBootstrap()
	if bs.AuthCSRFSecureCookie && r.TLS == nil {
		hint = " (AUTENTICO_CSRF_SECURE_COOKIE=true but request is HTTP — cookie was not sent)"
	}

	slog.Warn("csrf validation failed",
		"request_id", requestID,
		"reason", fmt.Sprintf("%v%s", reason, hint),
		"ip", utils.GetClientIP(r),
		"url", r.URL.String(),
	)

	http.Error(w, fmt.Sprintf("Forbidden - CSRF token invalid: %v%s", reason, hint), http.StatusForbidden)
}

func CSRFMiddleware(next http.Handler) http.Handler {
	bs := config.GetBootstrap()
	return csrf.Protect(
		[]byte(bs.AuthCSRFProtectionSecretKey),
		csrf.Secure(bs.AuthCSRFSecureCookie),
		csrf.TrustedOrigins([]string{bs.AppHost}),
		csrf.ErrorHandler(http.HandlerFunc(csrfErrorHandler)),
	)(next)
}
