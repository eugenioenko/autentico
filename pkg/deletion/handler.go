package deletion

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/middleware"
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
	usr := middleware.UserFromContext(r.Context())
	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var input CreateDeletionRequestInput
	_ = json.NewDecoder(r.Body).Decode(&input)

	if config.Get().AllowSelfServiceDeletion {
		if err := HardDeleteUser(usr.ID); err != nil {
			slog.Error("deletion: failed to delete user (self-service)", "error", err, "user_id", usr.ID)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to delete account")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Check if a pending request already exists
	existing, err := DeletionRequestByUserID(usr.ID)
	if err != nil {
		slog.Error("deletion: failed to check existing request", "error", err, "user_id", usr.ID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to process deletion request")
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
		slog.Error("deletion: failed to create deletion request", "error", err, "user_id", usr.ID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create deletion request")
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
	usr := middleware.UserFromContext(r.Context())
	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	req, err := DeletionRequestByUserID(usr.ID)
	if err != nil {
		slog.Error("deletion: failed to get deletion request", "error", err, "user_id", usr.ID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get deletion request")
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
	usr := middleware.UserFromContext(r.Context())
	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	req, err := DeletionRequestByUserID(usr.ID)
	if err != nil {
		slog.Error("deletion: failed to get deletion request for cancel", "error", err, "user_id", usr.ID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get deletion request")
		return
	}
	if req == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "No pending deletion request found")
		return
	}

	if err := CancelDeletionRequest(req.ID); err != nil {
		slog.Error("deletion: failed to cancel deletion request", "error", err, "request_id", req.ID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to cancel deletion request")
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
	dateWhere, dateArgs, dateErr := api.ParseDateRange(r, map[string]string{
		"requested_at": "d.requested_at",
	})
	if dateErr != nil {
		utils.ErrorResponse(w, dateErr.Error(), http.StatusBadRequest)
		return
	}

	requests, total, err := ListDeletionRequestsWithParams(params, dateWhere, dateArgs)
	if err != nil {
		slog.Error("deletion: failed to list deletion requests", "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list deletion requests")
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
		slog.Error("deletion: failed to get deletion request", "error", err, "request_id", id)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get deletion request")
		return
	}
	if req == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Deletion request not found")
		return
	}

	if err := HardDeleteUser(req.UserID); err != nil {
		slog.Error("deletion: failed to delete user (admin approve)", "error", err, "user_id", req.UserID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to delete user")
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
		slog.Error("deletion: failed to cancel deletion request (admin)", "error", err, "request_id", id)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to cancel deletion request")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
