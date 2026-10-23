// Package revoke implements the OAuth 2.0 Token Revocation endpoint
// (RFC 7009) — /oauth2/revoke.
package revoke

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleRevoke godoc
// @Summary Revoke a token
// @Description Revokes an access or refresh token
// @Tags oauth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param token formData string true "Token to revoke"
// @Success 200 {string} string "Token revoked successfully"
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.AuthErrorResponse "Client authentication failed; matching WWW-Authenticate challenge"
// @Failure 403 {object} model.ApiError "Bearer token lacks admin audience or role"
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
		// RFC 7009 §2.1 / RFC 6749 §5.2: malformed authentication is not
		// an invalid password or an invitation to try another mechanism.
		if errors.Is(err, client.ErrInvalidClientAuthenticationRequest) {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		slog.Warn("revoke: client authentication failed", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteBasicUnauthorized(w, "revocation", "Client authentication failed")
		return
	}
	if authenticatedClient == nil {
		// RFC 7662 §2.1 / RFC 6750: alternatively accept an admin Bearer token
		if r.Header.Get("Authorization") == "" {
			utils.WriteBasicUnauthorized(w, "revocation", "Client authentication required")
			return
		}
		v, err := bearer.ValidateBearer(r)
		if err != nil {
			slog.Warn("revoke: bearer auth failed", "request_id", reqid.Get(r.Context()), "error", err)
			utils.WriteBearerUnauthorized(w, config.GetBootstrap().AppAuthIssuer, "invalid_token", "Bearer token is invalid, expired, or its session has been revoked")
			return
		}
		// RFC 6750 §5.2: privileged revocation requires the admin resource audience.
		if err := jwtutil.ValidateAudience(v.Claims.Audience, []string{config.AdminClientID}); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			utils.WriteErrorResponse(w, http.StatusForbidden, "insufficient_scope", "Token not issued for admin API")
			return
		}
		usr, err := user.UserByID(v.Claims.UserID)
		if err != nil || usr.Role != "admin" {
			slog.Warn("revoke: bearer auth requires admin role", "request_id", reqid.Get(r.Context()), "user_id", v.Claims.UserID)
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			utils.WriteErrorResponse(w, http.StatusForbidden, "insufficient_scope", "Admin access required for bearer token revocation")
			return
		}
	}

	// RFC 7009 §2.1: parameters use application/x-www-form-urlencoded in the POST body
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
			slog.Info("revoke: token belongs to different client", "request_id", reqid.Get(r.Context()), "token_azp", azp, "caller", authenticatedClient.ClientID)
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
	_ = token.RevokeByTokenValue(tokenID)

	// RFC 7009 §2.2: the content of the response body is ignored by the client
	w.WriteHeader(http.StatusOK)
}
