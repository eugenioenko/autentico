package deletion

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleRequestDeletion godoc
// @Summary Request account deletion
// @Description Submits a deletion request for the authenticated user. If self-service deletion is enabled, the account is deleted immediately.
// @Tags account-deletion
// @Accept json
// @Produce json
// @Param body body CreateDeletionRequestInput false "Optional deletion reason"
// @Security UserAuth
// @Success 200 {object} DeletionRequestResponse
// @Success 204 "Account deleted immediately (self-service mode)"
// @Failure 401 {object} model.ApiError
// @Failure 409 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /account/api/deletion-request [post]
func HandleRequestDeletion(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var input CreateDeletionRequestInput
	_ = json.NewDecoder(r.Body).Decode(&input)

	if config.Get().AllowSelfServiceDeletion {
		if err := HardDeleteUser(usr.ID); err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Check if a pending request already exists
	existing, err := DeletionRequestByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing != nil {
		utils.WriteErrorResponse(w, http.StatusConflict, "already_requested", "A deletion request is already pending")
		return
	}

	var reason *string
	if input.Reason != "" {
		reason = &input.Reason
	}

	req, err := CreateDeletionRequest(usr.ID, reason)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, req.ToResponse(), http.StatusCreated)
}

// HandleGetDeletionRequest godoc
// @Summary Get pending deletion request for current user
// @Tags account-deletion
// @Produce json
// @Security UserAuth
// @Success 200 {object} DeletionRequestResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/deletion-request [get]
func HandleGetDeletionRequest(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	req, err := DeletionRequestByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if req == nil {
		utils.SuccessResponse(w, (*DeletionRequestResponse)(nil), http.StatusOK)
		return
	}
	utils.SuccessResponse(w, req.ToResponse(), http.StatusOK)
}

// HandleCancelDeletionRequest godoc
// @Summary Cancel the current user's pending deletion request
// @Tags account-deletion
// @Produce json
// @Security UserAuth
// @Success 204
// @Failure 401 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Router /account/api/deletion-request [delete]
func HandleCancelDeletionRequest(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	req, err := DeletionRequestByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if req == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "No pending deletion request found")
		return
	}

	if err := CancelDeletionRequest(req.ID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleListDeletionRequests godoc
// @Summary List all pending deletion requests
// @Tags admin-deletion
// @Produce json
// @Param sort query string false "Sort by field" Enums(requested_at, username, email) default(requested_at)
// @Param order query string false "Sort order" Enums(asc, desc) default(asc)
// @Param search query string false "Search by username, email, or reason"
// @Param requested_at_from query string false "Filter: requested at or after (ISO 8601)"
// @Param requested_at_to query string false "Filter: requested at or before (ISO 8601)"
// @Param limit query int false "Max results per page (1–100)" default(100)
// @Param offset query int false "Number of results to skip" default(0)
// @Security AdminAuth
// @Success 200 {object} model.ListResponse[DeletionRequestResponse]
// @Failure 500 {object} model.ApiError
// @Router /admin/api/deletion-requests [get]
func HandleListDeletionRequests(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	dateWhere, dateArgs := api.ParseDateRange(r, map[string]string{
		"requested_at": "d.requested_at",
	})

	requests, total, err := ListDeletionRequestsWithParams(params, dateWhere, dateArgs)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var items []DeletionRequestResponse
	for _, req := range requests {
		items = append(items, req.ToResponse())
	}
	if items == nil {
		items = []DeletionRequestResponse{}
	}
	utils.SuccessResponse(w, model.ListResponse[DeletionRequestResponse]{
		Items: items,
		Total: total,
	}, http.StatusOK)
}

// HandleApproveDeletionRequest godoc
// @Summary Approve a deletion request — permanently deletes the user
// @Tags admin-deletion
// @Produce json
// @Param id path string true "Deletion request ID"
// @Security AdminAuth
// @Success 204
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/deletion-requests/{id}/approve [post]
func HandleApproveDeletionRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing request id")
		return
	}

	req, err := DeletionRequestByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if req == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Deletion request not found")
		return
	}

	if err := HardDeleteUser(req.UserID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	audit.Log(audit.EventDeletionApproved, audit.ActorFromRequest(r), audit.TargetUser, req.UserID, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// HandleAdminCancelDeletionRequest godoc
// @Summary Cancel (dismiss) a deletion request without deleting the user
// @Tags admin-deletion
// @Produce json
// @Param id path string true "Deletion request ID"
// @Security AdminAuth
// @Success 204
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/deletion-requests/{id} [delete]
func HandleAdminCancelDeletionRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing request id")
		return
	}

	if err := CancelDeletionRequest(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Deletion request not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
