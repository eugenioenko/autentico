package introspect

import (
	"encoding/json"
	"log/slog"
	"net/http"

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

	// Decode and validate request body
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if req.Token == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Token is required")
		return
	}

	err = ValidateTokenIntrospectRequest(req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Per RFC 7662 §2.2: any token that is invalid, expired, revoked, or unknown
	// MUST return 200 {"active":false} — never a 4xx error.
	tkn, err := IntrospectToken(req.Token)
	if err != nil {
		slog.Info("introspect: inactive token", "request_id", middleware.GetRequestID(r.Context()), "reason", err)
		inactive(w)
		return
	}

	sess, err := session.SessionByAccessToken(tkn.AccessToken)
	if err != nil || sess == nil || sess.DeactivatedAt != nil {
		slog.Info("introspect: session not active", "request_id", middleware.GetRequestID(r.Context()))
		inactive(w)
		return
	}

	introspect := IntrospectResponse{
		Active:    true,
		Scope:     tkn.Scope,
		TokenType: tkn.AccessTokenType,
		Exp:       tkn.AccessTokenExpiresAt.Unix(),
		Iat:       tkn.IssuedAt.Unix(),
		Sub:       tkn.UserID,
		Jti:       tkn.ID,
	}

	utils.WriteApiResponse(w, introspect, http.StatusOK)
}
