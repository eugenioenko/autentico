package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	"autentico/pkg/config"
	. "autentico/pkg/models"
	"autentico/pkg/users"
	"autentico/pkg/utils"
)

// @Summary Create a new user
// @Description Registers a new user in the system
// @Tags auth
// @Accept json
// @Produce json
// @Param user body UserCreateRequest true "User creation payload"
// @Success 201 {object} ApiUserResponse
// @Router /create [post]
func CreateUser(w http.ResponseWriter, r *http.Request) {
	var req UserCreateRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		utils.ErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = ValidateUserCreateRequest(req)
	if err != nil {
		err = fmt.Errorf("User validation error. %w", err)
		utils.ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if config.ValidationUsernameIsEmail && req.Email == "" {
		req.Email = req.Username
	}

	response, err := users.CreateUser(req.Username, req.Password, req.Email)
	if err != nil {
		err = fmt.Errorf("User creation error. %w", err)
		utils.ErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.SuccessResponse(w, response, http.StatusCreated)
}
