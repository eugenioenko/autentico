package session

import (
	"net/http"

	"autentico/pkg/db"
	"autentico/pkg/utils"
)

func HandleLogout(w http.ResponseWriter, r *http.Request) {
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

	query := `
		UPDATE sessions
		SET deactivated_at = CURRENT_TIMESTAMP
		WHERE access_token = ?;
	`
	_, err := db.GetDB().Exec(query, accessToken)
	if err != nil {
		utils.ErrorResponse(w, "Failed to terminate session", http.StatusInternalServerError)
		return
	}

	utils.SuccessResponse(w, "Session terminated successfully", http.StatusOK)
}
