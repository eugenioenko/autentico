package idpsession

import (
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// IdpSessionResponse is the admin-facing JSON representation of an IdP session.
type IdpSessionResponse struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	UserAgent       string `json:"user_agent"`
	IPAddress       string `json:"ip_address"`
	LastActivityAt  string `json:"last_activity_at"`
	CreatedAt       string `json:"created_at"`
	ActiveAppsCount int    `json:"active_apps_count"`
}

func deviceRowsToResponse(devices []DeviceRow) []IdpSessionResponse {
	response := make([]IdpSessionResponse, 0, len(devices))
	for _, d := range devices {
		response = append(response, IdpSessionResponse{
			ID:              d.ID,
			UserID:          d.UserID,
			Username:        d.Username,
			Email:           d.Email,
			UserAgent:       d.UserAgent,
			IPAddress:       d.IPAddress,
			LastActivityAt:  d.LastActivityAt.Format(time.RFC3339),
			CreatedAt:       d.CreatedAt.Format(time.RFC3339),
			ActiveAppsCount: d.ActiveAppsCount,
		})
	}
	return response
}

// HandleListIdpSessions godoc
// @Summary List IdP (device) sessions
// @Description Returns all active IdP sessions with server-side sorting, search, and pagination.
// @Tags admin-sessions
// @Produce json
// @Param sort query string false "Sort field (last_activity_at, created_at)"
// @Param order query string false "Sort order (asc, desc)" default(asc)
// @Param search query string false "Search across username, email, and IP address"
// @Param limit query integer false "Max results per page (1–100)" default(100)
// @Param offset query integer false "Number of results to skip" default(0)
// @Param created_at_from query string false "Filter sessions created after (ISO 8601)"
// @Param created_at_to query string false "Filter sessions created before (ISO 8601)"
// @Param last_activity_at_from query string false "Filter sessions active after (ISO 8601)"
// @Param last_activity_at_to query string false "Filter sessions active before (ISO 8601)"
// @Security AdminAuth
// @Success 200 {object} model.ListResponse[IdpSessionResponse]
// @Router /admin/api/idp-sessions [get]
func HandleListIdpSessions(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	dateWhere, dateArgs := api.ParseDateRange(r, map[string]string{
		"created_at":       "s.created_at",
		"last_activity_at": "s.last_activity_at",
	})

	devices, total, err := ListIdpSessionsWithParams(params, dateWhere, dateArgs)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, model.ListResponse[IdpSessionResponse]{
		Items: deviceRowsToResponse(devices),
		Total: total,
	}, http.StatusOK)
}

// HandleListUserIdpSessions godoc
// @Summary List a user's IdP (device) sessions
// @Description Returns all active IdP sessions for a user with active OAuth app counts.
// @Tags admin-sessions
// @Produce json
// @Param id path string true "User ID"
// @Security AdminAuth
// @Success 200 {array} IdpSessionResponse
// @Router /admin/api/users/{id}/idp-sessions [get]
func HandleListUserIdpSessions(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}

	devices, err := ListActiveDevicesForUser(userID, time.Time{})
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, deviceRowsToResponse(devices), http.StatusOK)
}

// HandleForceLogoutIdpSession godoc
// @Summary Force sign-out a device (IdP session)
// @Description Deactivates an IdP session and cascades to all child OAuth sessions and tokens.
// @Tags admin-sessions
// @Produce json
// @Param id path string true "IdP Session ID"
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Router /admin/api/idp-sessions/{id} [delete]
func HandleForceLogoutIdpSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing idp session id")
		return
	}

	sess, err := IdpSessionByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "IdP session not found")
		return
	}

	if err := DeactivateWithCascade(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	if ReadCookie(r) == id {
		ClearCookie(w)
	}

	audit.Log(audit.EventSessionRevoked, audit.ActorFromRequest(r), audit.TargetSession, id,
		audit.Detail("type", "idp_session", "user_id", sess.UserID), utils.GetClientIP(r))

	utils.SuccessResponse(w, map[string]string{"result": "deactivated"}, http.StatusOK)
}
