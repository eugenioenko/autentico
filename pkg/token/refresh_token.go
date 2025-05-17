package token

import (
	"autentico/pkg/config"
	"autentico/pkg/session"
	"autentico/pkg/user"
	"autentico/pkg/utils"
	"fmt"
	"net/http"
	"time"
)

func UserByRefreshToken(w http.ResponseWriter, request TokenRequest) (*user.User, error) {
	err := ValidateTokenRequestRefresh(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", fmt.Sprintf("Invalid or expired refresh token: %v", err))
		return nil, err
	}

	authToken, err := DecodeRefreshToken(request.RefreshToken, config.Get().AuthRefreshTokenSecret)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", fmt.Sprintf("Invalid or expired refresh token: %v", err))
		return nil, err
	}

	if time.Now().After(time.Unix(authToken.ExpiresAt, 0)) {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", "Refresh token has expired")
		return nil, err
	}

	sess, err := session.SessionByID(authToken.SessionID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", fmt.Sprintf("Failed to retrieve session: %v", err))
		return nil, err
	}

	if sess == nil || sess.DeactivatedAt != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", "Session has been deactivated")
		return nil, err
	}

	usr, err := user.UserByID(authToken.UserID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Failed to retrieve user: %v", err))
		return nil, err
	}
	return usr, nil
}
