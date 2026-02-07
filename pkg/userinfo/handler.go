package userinfo

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleUserInfo godoc
// @Summary Get user information
// @Description Retrieves user information based on the access token
// @Tags userinfo
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/userinfo [get]
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

	// Validate the access token cryptographically
	_, err := jwtutil.ValidateAccessToken(accessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Token is invalid or expired")
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
