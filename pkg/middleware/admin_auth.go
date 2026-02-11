package middleware

import (
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
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Missing Authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Invalid Authorization header format")
			return
		}

		tokenString := parts[1]
		claims, err := jwtutil.ValidateAccessToken(tokenString)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		if err := jwtutil.ValidateAudience(claims.Audience, config.Get().AuthAccessTokenAudience); err != nil {
			utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Invalid token audience")
			return
		}

		// Get user and check admin role
		usr, err := user.UserByID(claims.UserID)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "User not found")
			return
		}

		if usr.Role != "admin" {
			utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Admin access required")
			return
		}

		// Check if the session associated with this token is still active
		sess, err := session.SessionByAccessToken(tokenString)
		if err != nil || sess == nil || sess.DeactivatedAt != nil {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Session has been deactivated")
			return
		}

		next.ServeHTTP(w, r)
	})
}
