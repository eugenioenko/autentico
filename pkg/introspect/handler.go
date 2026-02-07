package introspect

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/utils"
)

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

	// Validate the access token cryptographically
	_, err = jwtutil.ValidateAccessToken(req.Token)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Token is invalid or expired")
		return
	}

	err = ValidateTokenIntrospectRequest(req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	tkn, err := IntrospectToken(req.Token)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Token is invalid or expired")
		return
	}

	sess, err := session.SessionByAccessToken(tkn.AccessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", fmt.Sprintf("Failed to retrieve session: %v", err))
		return
	}

	if sess == nil || sess.DeactivatedAt != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", "Session has been deactivated")
		return
	}

	introspect := IntrospectResponse{
		Active:    true,
		Scope:     tkn.Scope,
		ClientID:  config.Get().AuthDefaultClientID,
		TokenType: tkn.AccessTokenType,
		Exp:       tkn.AccessTokenExpiresAt.Unix(),
		Iat:       tkn.IssuedAt.Unix(),
		Sub:       tkn.UserID,
		Jti:       tkn.ID,
	}

	utils.WriteApiResponse(w, introspect, http.StatusOK)
}
