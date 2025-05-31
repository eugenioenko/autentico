package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleCreateUser godoc
// @Summary Create a new user
// @Description Registers a new user in the system
// @Tags users
// @Accept json
// @Produce json
// @Param user body UserCreateRequest true "User creation payload"
// @Success 201 {object} UserResponse
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /users/create [post]
func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var request UserCreateRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}

	err = ValidateUserCreateRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("User validation error. %v", err))
		return
	}

	if config.Get().ValidationUsernameIsEmail && request.Email == "" {
		request.Email = request.Username
	}

	response, err := CreateUser(request.Username, request.Password, request.Email)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("User creation error. %v", err))
		return
	}

	utils.SuccessResponse(w, response, http.StatusCreated)
}
