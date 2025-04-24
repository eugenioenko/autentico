package token

import (
	"net/http"
	"time"

	"autentico/pkg/db"
	"autentico/pkg/utils"
)

func RevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.ErrorResponse(w, "Only POST method is allowed", http.StatusBadRequest)
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.ErrorResponse(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	tokenID := r.FormValue("token")
	if tokenID == "" {
		utils.ErrorResponse(w, "Token is required", http.StatusBadRequest)
		return
	}

	query := `
		UPDATE tokens
		SET revoked_at = ?
		WHERE access_token = ? OR refresh_token = ?;
	`
	_, err = db.GetDB().Exec(query, time.Now().UTC(), tokenID, tokenID)
	if err != nil {
		utils.ErrorResponse(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	utils.SuccessResponse(w, "Token revoked successfully", http.StatusOK)
}
