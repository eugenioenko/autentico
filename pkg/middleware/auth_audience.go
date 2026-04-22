package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// AuthAudienceMiddleware checks that the JWT token has the correct audience (aud claim)
func AuthAudienceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := config.GetBootstrap().AppAuthIssuer
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "", "")
			return
		}
		// RFC 6750 §2.1 / RFC 7235: scheme name is case-insensitive
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_request", "Invalid Authorization header format")
			return
		}
		tokenString := parts[1]
		claims, err := jwtutil.ValidateAccessToken(tokenString)
		if err != nil {
			slog.Warn("auth_audience: invalid or expired token", "request_id", reqid.Get(r.Context()), "error", err, "ip", utils.GetClientIP(r))
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Invalid or expired token")
			return
		}
		if err := jwtutil.ValidateAudience(claims.Audience, config.Get().AuthAccessTokenAudience); err != nil {
			slog.Warn("auth_audience: invalid token audience", "request_id", reqid.Get(r.Context()), "ip", utils.GetClientIP(r))
			utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Invalid token audience")
			return
		}
		next.ServeHTTP(w, r)
	})
}
