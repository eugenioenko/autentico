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
	// RFC 7009 §2.1: revocation request is an HTTP POST with form-encoded body
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Only POST method is allowed")
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	// RFC 7009 §2.1: "token" parameter is REQUIRED
	tokenID := r.FormValue("token")
	if tokenID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Token is required")
		return
	}

	// RFC 7009 §2.1: "token_type_hint" is OPTIONAL; an authorization server MAY
	// ignore this parameter — we search both columns regardless.
	// RFC 7009 §2.2: an invalid token_type_hint value is ignored and does not
	// influence the revocation response.

	// RFC 7009 §2.2: respond with HTTP 200 whether the token is valid, invalid,
	// or unknown — the UPDATE is simply a no-op if the token is not found.
	// RFC 7009 §2.2: revoking a refresh token SHOULD also invalidate access tokens
	// based on the same authorization grant — our schema stores both on the same row,
	// so setting revoked_at on the row invalidates both tokens simultaneously.
	query := `
		UPDATE tokens
		SET revoked_at = ?
		WHERE access_token = ? OR refresh_token = ?;
	`
	_, err = db.GetDB().Exec(query, time.Now().UTC(), tokenID, tokenID)
	if err != nil {
		// RFC 7009 §2.2: do not leak information; always return 200
		w.WriteHeader(http.StatusOK)
		return
	}

	// RFC 7009 §2.2: the content of the response body is ignored by the client
	w.WriteHeader(http.StatusOK)
}
