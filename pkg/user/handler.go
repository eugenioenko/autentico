package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// GetUserFromRequest extracts the user and role from the Authorization header
func GetUserFromRequest(r *http.Request) (*User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	tokenStr := utils.ExtractBearerToken(authHeader)
	if tokenStr == "" {
		return nil, fmt.Errorf("invalid Authorization header")
	}
	if _, err := jwtutil.ValidateAccessToken(tokenStr); err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}
	// Find session by access token
	session, err := session.SessionByAccessToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %v", err)
	}
	// Find user by session.UserID
	user, err := UserByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %v", err)
	}
	return user, nil
}

// HandleCreateUser godoc
// @Summary Create a new user
// @Description Registers a new user in the system (admin only)
// @Tags users-admin
// @Accept json
// @Produce json
// @Param user body UserCreateRequest true "User creation payload"
// @Security BearerAuth
// @Success 201 {object} UserResponse
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users [post]
func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var request UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	err := ValidateUserCreateRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("User validation error. %v", err))
		return
	}
	if config.Get().ProfileFieldEmail == "is_username" && request.Email == "" {
		request.Email = request.Username
	}
	response, err := CreateUser(request.Username, request.Password, request.Email)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("User creation error. %v", err))
		return
	}
	utils.SuccessResponse(w, response, http.StatusCreated)
}

// HandleGetUser godoc
// @Summary Get a user by ID
// @Tags users-admin
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} UserResponse
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Router /admin/api/users/{id} [get]
func HandleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}

// HandleUpdateUser godoc
// @Summary Update a user
// @Tags users-admin
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body UserUpdateRequest true "User update payload"
// @Security BearerAuth
// @Success 200 {object} UserResponse
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users/{id} [put]
func HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	var req UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	// In is_username mode, keep username and email in sync
	if config.Get().ProfileFieldEmail == "is_username" && req.Username != "" {
		req.Email = req.Username
	}
	if err := ValidateUserUpdateRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	err := UpdateUser(id, req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}

// HandleDeleteUser godoc
// @Summary Delete a user
// @Tags users-admin
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users/{id} [delete]
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	err := DeleteUser(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, map[string]string{"result": "deleted"}, http.StatusOK)
}

// HandleListUsers godoc
// @Summary List all users
// @Tags users-admin
// @Produce json
// @Security BearerAuth
// @Success 200 {array} UserResponse
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users [get]
func HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := ListUsers()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []UserResponse
	for _, u := range users {
		response = append(response, u.ToResponse())
	}

	if response == nil {
		response = []UserResponse{}
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleUnlockUser unlocks a user account after multiple failed login attempts.
// @Summary Unlock user account
// @Description Resets the failed login attempts and clears the lockout time for a user.
// @Tags users-admin
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} UserResponse
// @Router /admin/api/users/{id}/unlock [post]
func HandleUnlockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	err := UnlockUser(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}
