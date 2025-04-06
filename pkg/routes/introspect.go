package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	"autentico/pkg/auth"
	. "autentico/pkg/model"
	"autentico/pkg/utils"
)

func IntrospectToken(w http.ResponseWriter, r *http.Request) {
	var req IntrospectRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		utils.ErrorResponse(w, "invalid_request", http.StatusBadRequest)
		return
	}

	err = ValidateTokenIntrospectRequest(req)
	if err != nil {
		utils.ErrorResponse(w, "invalid_request", http.StatusBadRequest)
		return
	}

	res, err := auth.IntrospectToken(req.Token)
	if err != nil {
		err = fmt.Errorf("todo. %w", err)
		utils.ErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.SuccessResponse(w, res, http.StatusCreated)
}
