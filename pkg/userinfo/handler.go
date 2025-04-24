package userinfo

import (
	"net/http"

	"autentico/pkg/introspect"
	"autentico/pkg/user"
	"autentico/pkg/utils"
)

func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_request", "Authorization header is required")
		return
	}

	accessToken := utils.ExtractBearerToken(authHeader)
	if accessToken == "" {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_request", "Invalid Authorization header")
		return
	}

	tok, err := introspect.IntrospectToken(accessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
		return
	}

	user, err := user.UserByID(tok.UserID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Unable to fetch user information")
		return
	}

	response := map[string]interface{}{
		"sub":      tok.UserID,
		"email":    user.Email,
		"username": user.Username,
		"scope":    tok.Scope,
	}
	utils.WriteApiResponse(w, response, http.StatusOK)
}
