package session

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleLogout godoc
// @Summary Log out a user
// @Description Terminates the user's session
// @Tags session
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {string} string "Session terminated successfully"
// @Failure 401 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/logout [post]
func HandleLogout(w http.ResponseWriter, r *http.Request) {
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

	query := `
		UPDATE sessions
		SET deactivated_at = CURRENT_TIMESTAMP
		WHERE access_token = ?;
	`
	_, err := db.GetDB().Exec(query, accessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to terminate session")
		return
	}

	utils.SuccessResponse(w, "ok", http.StatusOK)
}
