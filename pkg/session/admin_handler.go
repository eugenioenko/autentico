package session

import (
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListSessions godoc
// @Summary List sessions
// @Description Lists all active sessions, optionally filtered by user ID.
// @Tags sessions-admin
// @Produce json
// @Param user_id query string false "Filter by User ID"
// @Security BearerAuth
// @Success 200 {array} SessionResponse
// @Router /admin/api/sessions [get]
func HandleListSessions(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	var (
		sessions []*Session
		err      error
	)

	if userID != "" {
		sessions, err = ListSessionsByUser(userID)
	} else {
		sessions, err = ListSessions()
	}

	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	response := make([]SessionResponse, 0, len(sessions))
	for _, s := range sessions {
		response = append(response, s.ToResponse())
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleDeactivateSession godoc
// @Summary Deactivate a session
// @Tags sessions-admin
// @Produce json
// @Param id path string true "Session ID"
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Router /admin/api/sessions/{id} [delete]
func HandleDeactivateSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing session id")
		return
	}

	if err := DeactivateSessionByID(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Session not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	audit.Log(audit.EventSessionRevoked, audit.ActorFromRequest(r), audit.TargetSession, id, nil, utils.GetClientIP(r))
	utils.SuccessResponse(w, map[string]string{"result": "deactivated"}, http.StatusOK)
}
