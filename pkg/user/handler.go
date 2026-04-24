package user

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleCreateUser godoc
// @Summary Create a new user
// @Description Registers a new user in the system (admin only)
// @Tags admin-users
// @Accept json
// @Produce json
// @Param user body UserCreateRequest true "User creation payload"
// @Security AdminAuth
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
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	err := ValidateUserCreateRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("User validation error. %v", err))
		return
	}
	if config.Get().ProfileFieldEmail == "is_username" && request.Email == "" {
		request.Username = strings.ToLower(request.Username)
		request.Email = request.Username
	}
	response, err := CreateUser(request.Username, request.Password, request.Email)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "A user with that username or email already exists")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("User creation error. %v", err))
		return
	}
	admin := audit.ActorFromRequest(r)
	audit.Log(audit.EventUserCreated, admin, audit.TargetUser, response.ID, audit.Detail("source", "admin"), utils.GetClientIP(r))
	utils.SuccessResponse(w, response, http.StatusCreated)
}

// HandleGetUser godoc
// @Summary Get a user by ID
// @Tags admin-users
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
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
// @Tags admin-users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body UserUpdateRequest true "User update payload"
// @Security AdminAuth
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
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	// In is_username mode, keep username and email in sync
	if config.Get().ProfileFieldEmail == "is_username" && req.Username != "" {
		req.Username = strings.ToLower(req.Username)
		req.Email = req.Username
	}
	if err := ValidateUserUpdateRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	err := UpdateUser(id, req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	admin := audit.ActorFromRequest(r)
	audit.Log(audit.EventUserUpdated, admin, audit.TargetUser, id, nil, utils.GetClientIP(r))
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}

// HandleDeleteUser godoc
// @Summary Permanently delete a user
// @Description Hard-deletes a user and all associated data (tokens, sessions, group memberships, passkeys, etc.)
// @Tags admin-users
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
// @Success 204
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users/{id} [delete]
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	// Check user exists (including deactivated users)
	u, err := UserByIDIncludingDeactivated(id)
	if err != nil || u == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	if err := HardDeleteUser(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	admin := audit.ActorFromRequest(r)
	audit.Log(audit.EventUserDeleted, admin, audit.TargetUser, id, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeactivateUser godoc
// @Summary Deactivate a user
// @Description Soft-disables a user account, immediately revoking all tokens and deactivating all sessions.
// @Tags admin-users
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
// @Success 204
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users/{id}/deactivate [post]
func HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	err := DeactivateUser(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found or already deactivated")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	admin := audit.ActorFromRequest(r)
	audit.Log(audit.EventUserDeactivated, admin, audit.TargetUser, id, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// HandleReactivateUser godoc
// @Summary Reactivate a deactivated user
// @Description Clears the deactivated status, allowing the user to log in again.
// @Tags admin-users
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
// @Success 204
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users/{id}/reactivate [post]
func HandleReactivateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	err := ReactivateUser(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found or not deactivated")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	admin := audit.ActorFromRequest(r)
	audit.Log(audit.EventUserReactivated, admin, audit.TargetUser, id, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// HandleListUsers godoc
// @Summary List all users
// @Tags admin-users
// @Produce json
// @Security AdminAuth
// @Success 200 {array} UserResponse
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users [get]
func HandleListUsers(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	params.Filters = api.ParseFilters(r, userListConfig.AllowedFilters)
	if groupName := r.URL.Query().Get("group"); groupName != "" {
		params.Filters["group"] = groupName
	}

	users, total, err := ListUsersWithParams(params)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	userIDs := make([]string, len(users))
	for i, u := range users {
		userIDs[i] = u.ID
	}
	groupMap, _ := group.GroupNamesByUserIDs(userIDs)

	var items []UserResponse
	for _, u := range users {
		resp := u.ToResponse()
		if names, ok := groupMap[u.ID]; ok {
			resp.Groups = names
		}
		items = append(items, resp)
	}
	if items == nil {
		items = []UserResponse{}
	}

	utils.SuccessResponse(w, model.ListResponse[UserResponse]{
		Items: items,
		Total: total,
	}, http.StatusOK)
}

// HandleUnlockUser unlocks a user account after multiple failed login attempts.
// @Summary Unlock user account
// @Description Resets the failed login attempts and clears the lockout time for a user.
// @Tags admin-users
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
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
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	admin := audit.ActorFromRequest(r)
	audit.Log(audit.EventUserUnlocked, admin, audit.TargetUser, id, nil, utils.GetClientIP(r))
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}
