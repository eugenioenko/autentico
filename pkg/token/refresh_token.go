package token

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func UserByRefreshToken(w http.ResponseWriter, request TokenRequest) (*user.User, error) {
	err := ValidateTokenRequestRefresh(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("Invalid or expired refresh token: %v", err))
		return nil, err
	}

	authToken, err := DecodeRefreshToken(request.RefreshToken, config.GetBootstrap().AuthRefreshTokenSecret)
	if err != nil {
		slog.Warn("token: invalid refresh token", "error", err)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("Invalid or expired refresh token: %v", err))
		return nil, err
	}

	if time.Now().After(time.Unix(authToken.ExpiresAt, 0)) {
		slog.Warn("token: refresh token expired")
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Refresh token has expired")
		return nil, err
	}

	sess, err := session.SessionByID(authToken.SessionID)
	if err != nil {
		slog.Warn("token: session not found for refresh token", "error", err, "session_id", authToken.SessionID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("Failed to retrieve session: %v", err))
		return nil, err
	}

	if sess == nil || sess.DeactivatedAt != nil {
		slog.Warn("token: refresh token session deactivated", "session_id", authToken.SessionID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Session has been deactivated")
		return nil, fmt.Errorf("session has been deactivated")
	}

	// RFC 6749 §10.4: refresh token MUST be bound to the client it was issued to;
	// presenting a refresh token issued to a different client MUST be rejected.
	if authToken.ClientID != "" && request.ClientID != "" && authToken.ClientID != request.ClientID {
		slog.Warn("token: refresh token client mismatch", "token_client", authToken.ClientID, "request_client", request.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Refresh token was not issued to this client")
		return nil, fmt.Errorf("refresh token client mismatch")
	}

	// Check if the token has been revoked.
	// RFC 6819 §5.2.2.3: a revoked refresh token being presented indicates that
	// token rotation occurred and someone (attacker or legitimate user) is replaying
	// a stale token. Revoke all tokens for this user as a protective measure.
	var revokedAt *time.Time
	err = db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE refresh_token = ?`, request.RefreshToken).Scan(&revokedAt)
	if err == nil && revokedAt != nil {
		slog.Warn("token: rotated refresh token replayed — revoking all user tokens",
			"user_id", authToken.UserID)
		_, _ = db.GetDB().Exec(
			`UPDATE tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
			time.Now().UTC(), authToken.UserID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Token has been revoked")
		return nil, fmt.Errorf("token has been revoked")
	}

	usr, err := user.UserByID(authToken.UserID)
	if err != nil {
		slog.Error("token: failed to retrieve user for refresh token", "error", err, "user_id", authToken.UserID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Failed to retrieve user: %v", err))
		return nil, err
	}
	return usr, nil
}
