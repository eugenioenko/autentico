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
		utils.WriteApiResponse(w,
			IntrospectResponse{Error: "invalid_request", ErrorDescription: err.Error()},
			http.StatusBadRequest,
		)
		return
	}

	err = ValidateTokenIntrospectRequest(req)
	if err != nil {
		utils.WriteApiResponse(w,
			IntrospectResponse{Error: "invalid_request", ErrorDescription: err.Error()},
			http.StatusForbidden,
		)
		return
	}

	res, err := IntrospectToken(req.Token)
	if err != nil {
		utils.WriteApiResponse(w, IntrospectResponse{Error: "invalid_token",
			ErrorDescription: err.Error()},
			http.StatusForbidden,
		)
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
