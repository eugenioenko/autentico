package middleware

import (
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// AuthAudienceMiddleware checks that the JWT token has the correct audience (aud claim)
func AuthAudienceMiddleware(next http.Handler) http.Handler {
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
		next.ServeHTTP(w, r)
	})
}
