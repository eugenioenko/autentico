package introspect

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// inactive returns the RFC 7662 §2.2 required response for any token that is
// not active: HTTP 200 with {"active":false} and no additional claims.
func inactive(w http.ResponseWriter) {
	utils.WriteApiResponse(w, IntrospectResponse{Active: false}, http.StatusOK)
}

// HandleIntrospect godoc
// @Summary Introspect a token
// @Description Validates and retrieves metadata about a token
// @Tags introspect
// @Accept json
// @Produce json
// @Param token body IntrospectRequest true "Token introspection payload"
// @Success 200 {object} IntrospectResponse
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 429 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/introspect [post]
func HandleIntrospect(w http.ResponseWriter, r *http.Request) {

	var req IntrospectRequest

	if r.Body == nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request body is empty")
		return
	}

	// RFC 7662 §2.1: request MUST be application/x-www-form-urlencoded.
	// Also accept application/json for backwards compatibility with existing callers.
	var err error
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err = r.ParseForm(); err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
			return
		}
		// RFC 7662 §2.1: "token" parameter is REQUIRED
		req.Token = r.FormValue("token")
	} else {
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
			return
		}
	}

	// RFC 7662 §2.1: "token" is REQUIRED
	if req.Token == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Token is required")
		return
	}

	err = ValidateTokenIntrospectRequest(req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// RFC 7662 §2.2: any token that is invalid, expired, revoked, or unknown
	// MUST return 200 {"active":false} — never a 4xx error.
	tkn, err := IntrospectToken(req.Token)
	if err != nil {
		slog.Info("introspect: inactive token", "request_id", middleware.GetRequestID(r.Context()), "reason", err)
		inactive(w)
		return
	}

	// RFC 7662 §4: check session liveness — deactivated sessions mean the token
	// should no longer be considered active.
	sess, err := session.SessionByAccessToken(tkn.AccessToken)
	if err != nil || sess == nil || sess.DeactivatedAt != nil {
		slog.Info("introspect: session not active", "request_id", middleware.GetRequestID(r.Context()))
		inactive(w)
		return
	}

	// RFC 7662 §2.2: active token response — "active" is REQUIRED, all other fields OPTIONAL.
	// Note: client_id and username are not stored in the tokens table — omitted per spec allowance.
	aud := strings.Join(config.Get().AuthAccessTokenAudience, " ")
	introspect := IntrospectResponse{
		Active:    true,
		Scope:     tkn.Scope,
		TokenType: tkn.AccessTokenType,
		Exp:       tkn.AccessTokenExpiresAt.Unix(),
		Iat:       tkn.IssuedAt.Unix(),
		Sub:       tkn.UserID,
		Iss:       config.GetBootstrap().AppAuthIssuer,
		Aud:       aud,
		Jti:       tkn.ID,
	}

	utils.WriteApiResponse(w, introspect, http.StatusOK)
}
