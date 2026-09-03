package userclaim

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListUserClaims godoc
// @Summary List custom claims for a user
// @Tags admin-user-claims
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
// @Success 200 {array} UserClaimResponse
// @Failure 500 {object} model.ApiError
// @Router /admin/api/users/{id}/claims [get]
func HandleListUserClaims(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	claims, err := ClaimsByUserID(userID)
	if err != nil {
		slog.Error("userclaim: failed to list claims", "error", err, "user_id", userID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list claims")
		return
	}
	utils.SuccessResponse(w, claims, http.StatusOK)
}

// HandleUpsertUserClaim godoc
// @Summary Create or update a custom claim for a user
// @Tags admin-user-claims
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param claim body UserClaimRequest true "Custom claim payload"
// @Security AdminAuth
// @Success 201 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Router /admin/api/users/{id}/claims [post]
func HandleUpsertUserClaim(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	var req UserClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	// OIDC Core §5.1.2 / RFC 9068 §2.2.2: custom claims must not collide with
	// standard/structural claims — reserved names are rejected here at write time.
	if err := ValidateUserClaimRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := UpsertClaim(userID, req.Name, req.Value); err != nil {
		if strings.Contains(err.Error(), "user not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		slog.Error("userclaim: failed to save claim", "error", err, "user_id", userID, "claim", req.Name)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to save claim")
		return
	}
	utils.SuccessResponse(w, map[string]string{"message": "claim saved"}, http.StatusCreated)
}

// HandleDeleteUserClaim godoc
// @Summary Delete a custom claim from a user
// @Tags admin-user-claims
// @Produce json
// @Param id path string true "User ID"
// @Param name path string true "Claim name"
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Failure 404 {object} model.ApiError
// @Router /admin/api/users/{id}/claims/{name} [delete]
func HandleDeleteUserClaim(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	name := strings.TrimSpace(r.PathValue("name"))
	if userID == "" || name == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id or claim name")
		return
	}
	if err := DeleteClaim(userID, name); err != nil {
		if strings.Contains(err.Error(), "claim not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Claim not found")
			return
		}
		slog.Error("userclaim: failed to delete claim", "error", err, "user_id", userID, "claim", name)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to delete claim")
		return
	}
	utils.SuccessResponse(w, map[string]string{"message": "claim removed"}, http.StatusOK)
}
