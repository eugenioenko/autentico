package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// AdminAuthMiddleware verifies that the request has a valid JWT token
// with an admin role. Used to protect admin-only endpoints.
func AdminAuthMiddleware(next http.Handler) http.Handler {
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
			slog.Warn("admin_auth: invalid or expired token", "error", err, "ip", utils.GetClientIP(r))
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Invalid or expired token")
			return
		}

		if err := jwtutil.ValidateAudience(claims.Audience, config.Get().AuthAccessTokenAudience); err != nil {
			slog.Warn("admin_auth: invalid token audience", "ip", utils.GetClientIP(r))
			utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Invalid token audience")
			return
		}

		// Get user and check admin role
		usr, err := user.UserByID(claims.UserID)
		if err != nil {
			slog.Warn("admin_auth: user not found", "user_id", claims.UserID, "ip", utils.GetClientIP(r))
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "User not found")
			return
		}

		if usr.Role != "admin" {
			slog.Warn("admin_auth: non-admin access attempt", "user_id", claims.UserID, "ip", utils.GetClientIP(r))
			utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Admin access required")
			return
		}

		// Check if the session associated with this token is still active
		sess, err := session.SessionByAccessToken(tokenString)
		if err != nil || sess == nil || sess.DeactivatedAt != nil {
			slog.Warn("admin_auth: deactivated session", "user_id", claims.UserID, "ip", utils.GetClientIP(r))
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Session has been deactivated")
			return
		}

		next.ServeHTTP(w, r)
	})
}
