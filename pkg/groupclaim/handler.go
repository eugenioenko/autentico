package groupclaim

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListGroupClaims godoc
// @Summary List custom claims for a group
// @Description Lists local names; members receive them as literal group.claim keys with the custom_claims scope.
// @Tags admin-group-claims
// @Produce json
// @Param id path string true "Group ID"
// @Security AdminAuth
// @Success 200 {object} model.ApiResponse[[]GroupClaimResponse]
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/groups/{id}/claims [get]
func HandleListGroupClaims(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if groupID == "" {
		// Group custom claims §4: a management request must identify its owner.
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id")
		return
	}
	// Group custom claims §4 (rfc/group-custom-claims.md): distinguish missing owners from storage failures.
	var exists int
	if err := db.GetDB().QueryRow("SELECT 1 FROM groups WHERE id = ?", groupID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Group custom claims §4: an unknown group is 404, not an empty claim list.
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Group not found")
			return
		}
		slog.Error("groupclaim: failed to find group", "error", err, "group_id", groupID)
		// Group custom claims §4: storage failures are 500, not missing owners.
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list claims")
		return
	}
	claims, err := ClaimsByGroupID(groupID)
	if err != nil {
		slog.Error("groupclaim: failed to list claims", "error", err, "group_id", groupID)
		// Group custom claims §4: failed reads must not masquerade as empty claims.
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list claims")
		return
	}
	// Group custom claims §4: lists use the existing custom-claim response envelope.
	utils.WriteApiResponse(w, model.ApiResponse[[]GroupClaimResponse]{Data: claims}, http.StatusOK)
}

// HandleUpsertGroupClaim godoc
// @Summary Create or update a custom claim for a group
// @Tags admin-group-claims
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param claim body GroupClaimRequest true "Custom claim payload"
// @Security AdminAuth
// @Success 201 {object} model.ApiResponse[map[string]string]
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/groups/{id}/claims [post]
func HandleUpsertGroupClaim(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if groupID == "" {
		// Group custom claims §4: reject a missing owner before writing.
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id")
		return
	}
	var req GroupClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Group custom claims §3–4: malformed string-claim payloads are invalid requests.
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	// OIDC Core §5.1.2 / RFC 9068 §2.2.2: custom claims must not collide with
	// standard/structural claims — group-local names are safely prefixed on emission.
	if err := ValidateGroupClaimRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := UpsertClaim(groupID, req.Name, req.Value); err != nil {
		if strings.Contains(err.Error(), "group not found") {
			// Group custom claims §4: cascading foreign-key ownership requires an existing group.
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Group not found")
			return
		}
		slog.Error("groupclaim: failed to save claim", "error", err, "group_id", groupID, "claim", req.Name)
		// Group custom claims §4, §6: failed writes return 500 without a success audit event.
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to save claim")
		return
	}
	// OWASP Logging Cheat Sheet (Event attributes / Data to exclude): identify the claim, never its potentially sensitive value.
	audit.Log(audit.EventGroupClaimUpserted, audit.ActorFromRequest(r), audit.TargetGroup, groupID, audit.Detail("claim_name", req.Name), utils.GetClientIP(r))
	// Group custom claims §4: creating and replacing a claim both return 201.
	utils.SuccessResponse(w, map[string]string{"message": "claim saved"}, http.StatusCreated)
}

// HandleDeleteGroupClaim godoc
// @Summary Delete a custom claim from a group
// @Tags admin-group-claims
// @Produce json
// @Param id path string true "Group ID"
// @Param name path string true "Claim name"
// @Security AdminAuth
// @Success 200 {object} model.ApiResponse[map[string]string]
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/groups/{id}/claims/{name} [delete]
func HandleDeleteGroupClaim(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	name := strings.TrimSpace(r.PathValue("name"))
	if groupID == "" || name == "" {
		// Group custom claims §4: identify both the group and its local claim.
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing group id or claim name")
		return
	}
	if err := DeleteClaim(groupID, name); err != nil {
		if strings.Contains(err.Error(), "claim not found") {
			// Group custom claims §4: deleting an absent assignment returns 404.
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Claim not found")
			return
		}
		slog.Error("groupclaim: failed to delete claim", "error", err, "group_id", groupID, "claim", name)
		// Group custom claims §4, §6: failed deletions return 500 without success auditing.
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to delete claim")
		return
	}
	// OWASP Logging Cheat Sheet (Event attributes / Data to exclude): identify the claim, never its potentially sensitive value.
	audit.Log(audit.EventGroupClaimDeleted, audit.ActorFromRequest(r), audit.TargetGroup, groupID, audit.Detail("claim_name", name), utils.GetClientIP(r))
	// Group custom claims §4: acknowledge only a successfully removed assignment.
	utils.SuccessResponse(w, map[string]string{"message": "claim removed"}, http.StatusOK)
}
