package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	"autentico/pkg/auth"
	"autentico/pkg/utils"
)

func LoginUser(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		utils.ErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	response, err := auth.LoginUser(creds.Username, creds.Password)
	if err != nil {
		utils.ErrorResponse(w, fmt.Sprintf("Login failed: %v", err), http.StatusInternalServerError)
		return
	}
	utils.SuccessResponse(w, response)
}
