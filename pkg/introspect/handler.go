package introspect

import (
	"encoding/json"
	"net/http"

	"autentico/pkg/config"
	"autentico/pkg/utils"
)

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
