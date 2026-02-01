package token

import (
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/utils"
)

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

	// Validate the access token cryptographically
	_, err = jwtutil.ValidateAccessToken(tokenID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Token is invalid or expired")
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
