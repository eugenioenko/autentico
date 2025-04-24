package userinfo

import (
	"net/http"

	"autentico/pkg/introspect"
	"autentico/pkg/utils"
)

func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		utils.ErrorResponse(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	accessToken := utils.ExtractBearerToken(authHeader)
	if accessToken == "" {
		utils.ErrorResponse(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tok, err := introspect.IntrospectToken(accessToken)
	if err != nil {
		utils.ErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"sub":   tok.UserID,
		"email": tok.Scope, // Replace with actual user email if available
		"scope": tok.Scope,
	}
	utils.SuccessResponse(w, response, http.StatusOK)
}
