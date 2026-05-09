package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// AccountAuthMiddleware verifies that the request has a valid JWT token
// issued for the account API (audience "autentico-account" or "autentico-admin").
func AccountAuthMiddleware(next http.Handler) http.Handler {
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
			slog.Warn("account_auth: invalid or expired token", "error", err, "ip", utils.GetClientIP(r))
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Invalid or expired token")
			return
		}

		// RFC 9068 §2.2.3: enforce that the token was issued for the account API.
		// Tokens from autentico-account naturally include "autentico-account" in aud.
		// Tokens from autentico-admin are also accepted for admin convenience.
		// Other clients can be granted access by adding "autentico-account" to their allowed_audiences.
		if err := jwtutil.ValidateAudience(claims.Audience, []string{config.AccountClientID, config.AdminClientID}); err != nil {
			slog.Warn("account_auth: token not issued for account API", "aud", claims.Audience, "ip", utils.GetClientIP(r))
			utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Token not issued for account API")
			return
		}

		usr, err := user.UserByID(claims.UserID)
		if err != nil || usr == nil {
			slog.Warn("account_auth: user not found", "user_id", claims.UserID, "ip", utils.GetClientIP(r))
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "User not found")
			return
		}

		// Check if the session associated with this token is still active
		sess, err := session.SessionByAccessToken(tokenString)
		if err != nil || sess == nil || sess.DeactivatedAt != nil {
			slog.Warn("account_auth: deactivated session", "user_id", claims.UserID, "ip", utils.GetClientIP(r))
			// RFC 6750 §3.1: MUST include WWW-Authenticate on 401 responses
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Session has been deactivated")
			return
		}

		// TokenByAccessToken filters revoked rows; any error is a rejection.
		if _, err := token.TokenByAccessToken(tokenString); err != nil {
			slog.Warn("account_auth: token lookup failed or revoked", "user_id", claims.UserID, "error", err, "ip", utils.GetClientIP(r))
			utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Token has been revoked")
			return
		}

		r = setAuthInfo(r, &AuthInfo{
			User:    usr,
			Token:   tokenString,
			Claims:  claims,
			Session: sess,
		})
		next.ServeHTTP(w, r)
	})
}
