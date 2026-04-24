package group

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListGroups godoc
// @Summary List all groups
// @Tags admin-groups
// @Produce json
// @Security AdminAuth
// @Success 200 {object} model.ListResponse[GroupResponse]
// @Router /admin/api/groups [get]
func HandleListGroups(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	params.Filters = api.ParseFilters(r, groupListConfig.AllowedFilters)

	groups, total, err := ListGroupsWithParams(params)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, model.ListResponse[GroupResponse]{
		Items: groups,
		Total: total,
	}, http.StatusOK)
}

// HandleCreateGroup godoc
// @Summary Create a new group
// @Tags admin-groups
// @Accept json
// @Produce json
// @Param group body GroupCreateRequest true "Group creation payload"
// @Security AdminAuth
// @Success 201 {object} GroupResponse
// @Failure 400 {object} model.ApiError
// @Router /admin/api/groups [post]
func HandleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var request GroupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	if err := ValidateGroupCreateRequest(request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	response, err := CreateGroup(request.Name, request.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			utils.WriteErrorResponse(w, http.StatusConflict, "conflict", "A group with that name already exists")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Group creation error. %v", err))
		return
	}
	utils.SuccessResponse(w, response, http.StatusCreated)
}

// HandleGetGroup godoc
// @Summary Get a group by ID
// @Tags admin-groups
// @Produce json
// @Param id path string true "Group ID"
// @Security AdminAuth
// @Success 200 {object} GroupResponse
// @Failure 404 {object} model.ApiError
// @Router /admin/api/groups/{id} [get]
func HandleGetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id")
		return
	}
	g, err := GroupByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	utils.SuccessResponse(w, g.ToResponse(), http.StatusOK)
}

// HandleUpdateGroup godoc
// @Summary Update a group
// @Tags admin-groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param group body GroupUpdateRequest true "Group update payload"
// @Security AdminAuth
// @Success 200 {object} GroupResponse
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Router /admin/api/groups/{id} [put]
func HandleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id")
		return
	}
	var req GroupUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	if err := ValidateGroupUpdateRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := UpdateGroup(id, req); err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Group not found")
			return
		}
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			utils.WriteErrorResponse(w, http.StatusConflict, "conflict", "A group with that name already exists")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	g, err := GroupByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, g.ToResponse(), http.StatusOK)
}

// HandleDeleteGroup godoc
// @Summary Delete a group
// @Tags admin-groups
// @Produce json
// @Param id path string true "Group ID"
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Failure 404 {object} model.ApiError
// @Router /admin/api/groups/{id} [delete]
func HandleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id")
		return
	}
	if err := DeleteGroup(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Group not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, map[string]string{"message": "group deleted"}, http.StatusOK)
}

// HandleListMembers godoc
// @Summary List members of a group
// @Tags admin-groups
// @Produce json
// @Param id path string true "Group ID"
// @Security AdminAuth
// @Success 200 {array} GroupMemberResponse
// @Router /admin/api/groups/{id}/members [get]
func HandleListMembers(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if groupID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id")
		return
	}
	if _, err := GroupByID(groupID); err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Group not found")
		return
	}
	members, err := MembersByGroupID(groupID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, members, http.StatusOK)
}

// HandleAddMember godoc
// @Summary Add a user to a group
// @Tags admin-groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param member body GroupMemberRequest true "Member payload"
// @Security AdminAuth
// @Success 201 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 409 {object} model.ApiError
// @Router /admin/api/groups/{id}/members [post]
func HandleAddMember(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if groupID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id")
		return
	}
	var req GroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	if req.UserID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user_id")
		return
	}
	if err := AddMember(groupID, req.UserID); err != nil {
		if strings.Contains(err.Error(), "already a member") {
			utils.WriteErrorResponse(w, http.StatusConflict, "conflict", err.Error())
			return
		}
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, map[string]string{"message": "member added"}, http.StatusCreated)
}

// HandleRemoveMember godoc
// @Summary Remove a user from a group
// @Tags admin-groups
// @Produce json
// @Param id path string true "Group ID"
// @Param user_id path string true "User ID"
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Failure 404 {object} model.ApiError
// @Router /admin/api/groups/{id}/members/{user_id} [delete]
func HandleRemoveMember(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	userID := r.PathValue("user_id")
	if groupID == "" || userID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id or user id")
		return
	}
	if err := RemoveMember(groupID, userID); err != nil {
		if strings.Contains(err.Error(), "not a member") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, map[string]string{"message": "member removed"}, http.StatusOK)
}

// HandleGetUserGroups godoc
// @Summary Get groups for a user
// @Tags admin-groups
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
// @Success 200 {array} GroupResponse
// @Router /admin/api/users/{id}/groups [get]
func HandleGetUserGroups(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	groups, err := GroupsByUserID(userID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, groups, http.StatusOK)
}
