package session

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleSessionAdminEndpoint is the combined handler for /admin/api/sessions
func HandleSessionAdminEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleListSessions(w, r)
	case http.MethodDelete:
		handleDeactivateSession(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

func handleListSessions(w http.ResponseWriter, r *http.Request) {
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

func handleDeactivateSession(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing session id")
		return
	}

	if err := DeactivateSessionByID(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"result": "deactivated"}, http.StatusOK)
}
