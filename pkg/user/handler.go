package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"autentico/pkg/config"
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
func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var request UserCreateRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		utils.ErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = ValidateUserCreateRequest(request)
	if err != nil {
		err = fmt.Errorf("User validation error. %w", err)
		utils.ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if config.Get().ValidationUsernameIsEmail && request.Email == "" {
		request.Email = request.Username
	}

	response, err := CreateUser(request.Username, request.Password, request.Email)
	if err != nil {
		err = fmt.Errorf("User creation error. %w", err)
		utils.ErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.SuccessResponse(w, response, http.StatusCreated)
}
