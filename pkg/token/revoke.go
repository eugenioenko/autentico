package token

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/user"
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
// @Tags oauth2
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

	// RFC 7009 §2.1: "The authorization server first validates the client
	// credentials (in case of a confidential client)."
	// We require client authentication for all callers to prevent unauthorized
	// token revocation, consistent with RFC 7662 §2.1 introspection auth.
	authenticatedClient, err := client.AuthenticateClientFromRequest(r)
	if err != nil {
		slog.Warn("revoke: client authentication failed", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}
	if authenticatedClient == nil {
		// RFC 7662 §2.1 / RFC 6750: alternatively accept an admin Bearer token
		if r.Header.Get("Authorization") == "" {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Client authentication required")
			return
		}
		v, err := bearer.ValidateBearer(r)
		if err != nil {
			slog.Warn("revoke: bearer auth failed", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Bearer token is invalid, expired, or its session has been revoked")
			return
		}
		usr, err := user.UserByID(v.Claims.UserID)
		if err != nil || usr.Role != "admin" {
			slog.Warn("revoke: bearer auth requires admin role", "request_id", middleware.GetRequestID(r.Context()), "user_id", v.Claims.UserID)
			utils.WriteErrorResponse(w, http.StatusForbidden, "insufficient_scope", "Admin access required for bearer token revocation")
			return
		}
	}

	err = r.ParseForm()
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

	// RFC 7009 §2.1: "The authorization server first validates the client
	// credentials ... and then verifies whether the token was issued to the
	// client making the revocation request."
	// Return 200 (no-op) for tokens belonging to other clients to avoid
	// leaking token existence per RFC 7009 §2.1.
	// Admin bearer auth (authenticatedClient == nil) skips this — admins can revoke any token.
	if authenticatedClient != nil {
		azp := jwtutil.ExtractAzp(tokenID)
		if azp != "" && azp != authenticatedClient.ClientID {
			slog.Info("revoke: token belongs to different client", "request_id", middleware.GetRequestID(r.Context()), "token_azp", azp, "caller", authenticatedClient.ClientID)
			w.WriteHeader(http.StatusOK)
			return
		}
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
