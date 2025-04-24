package session

import (
	"net/http"

	"autentico/pkg/db"
	"autentico/pkg/utils"
)

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
