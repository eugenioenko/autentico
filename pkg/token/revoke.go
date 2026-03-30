package token

import (
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// RevokeTokensByUserAndClient sets revoked_at on all non-revoked authorization_code
// grant tokens for the given user. Called when auth code reuse is detected per RFC 6749 §4.1.2.
// clientID is accepted for logging context but the tokens table has no client_id column.
func RevokeTokensByUserAndClient(userID, _ string) error {
	_, err := db.GetDB().Exec(`
		UPDATE tokens
		SET revoked_at = ?
		WHERE user_id = ? AND grant_type = 'authorization_code' AND revoked_at IS NULL
	`, time.Now().UTC(), userID)
	return err
}

// HandleRevoke godoc
// @Summary Revoke a token
// @Description Revokes an access or refresh token
// @Tags token
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param token formData string true "Token to revoke"
// @Success 200 {string} string "Token revoked successfully"
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/revoke [post]
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

	// Per RFC 7009 §2.2: respond with 200 whether the token is valid, invalid,
	// or unknown — the UPDATE is simply a no-op if the token is not found.
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
