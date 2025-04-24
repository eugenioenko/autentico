package token

import (
	"net/http"
	"time"

	"autentico/pkg/db"
	"autentico/pkg/utils"
)

func HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Only POST method is allowed")
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	tokenID := r.FormValue("token")
	if tokenID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Token is required")
		return
	}

	query := `
		UPDATE tokens
		SET revoked_at = ?
		WHERE access_token = ? OR refresh_token = ?;
	`
	_, err = db.GetDB().Exec(query, time.Now().UTC(), tokenID, tokenID)
	if err != nil {
		// avoiding leaking information about token
		w.WriteHeader(http.StatusOK)
		return
	}

	// intentionally empty response body
	w.WriteHeader(http.StatusOK)
}
