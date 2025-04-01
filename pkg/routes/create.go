package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	. "autentico/pkg/models"
	"autentico/pkg/users"
	"autentico/pkg/utils"
)

func CreateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		utils.ErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	response, err := users.CreateUser(user.Username, user.Password, user.Email)
	if err != nil {
		utils.ErrorResponse(w, fmt.Sprintf("Error creating user: %v", err), http.StatusInternalServerError)
		return
	}

	utils.SuccessResponse(w, response, http.StatusCreated)
}
