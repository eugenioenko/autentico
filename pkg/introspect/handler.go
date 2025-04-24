package introspect

import (
	"encoding/json"
	"net/http"

	"autentico/pkg/config"
	"autentico/pkg/utils"
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
// @Failure 500 {object} model.ApiError
// @Router /oauth2/introspect [post]
func HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	var req IntrospectRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	err = ValidateTokenIntrospectRequest(req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_request", err.Error())
		return
	}

	res, err := IntrospectToken(req.Token)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_token", err.Error())
		return
	}

	introspect := IntrospectResponse{
		Active:    true,
		Scope:     res.Scope,
		ClientID:  config.Get().AuthDefaultClientID,
		TokenType: res.AccessTokenType,
		Exp:       res.AccessTokenExpiresAt.Unix(),
		Iat:       res.IssuedAt.Unix(),
		Sub:       res.UserID,
		Jti:       res.ID,
	}
	utils.WriteApiResponse(w, introspect, http.StatusOK)
}
