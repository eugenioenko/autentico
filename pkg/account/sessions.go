package account

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListSessions godoc
// @Summary List current user's sessions
// @Description Returns all active sessions for the authenticated user, with the current session flagged.
// @Tags account-security
// @Produce json
// @Security UserAuth
// @Success 200 {array} SessionResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/sessions [get]
func HandleListSessions(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	authHeader := r.Header.Get("Authorization")
	currentToken := utils.ExtractBearerToken(authHeader)

	claims, err := jwtutil.ValidateAccessToken(currentToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	sessions, err := session.ListSessionsByUser(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []SessionResponse
	for _, s := range sessions {
		if s.DeactivatedAt != nil {
			continue
		}
		response = append(response, SessionResponse{
			ID:             s.ID,
			UserAgent:      s.UserAgent,
			IPAddress:      s.IPAddress,
			LastActivityAt: s.LastActivityAt,
			CreatedAt:      s.CreatedAt,
			IsCurrent:      s.ID == claims.SessionID,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleRevokeSession godoc
// @Summary Revoke a session
// @Description Revokes one of the authenticated user's sessions. Cannot revoke the current session.
// @Tags account-security
// @Produce json
// @Param id path string true "Session ID"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Router /account/api/sessions/{id} [delete]
func HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing session ID")
		return
	}

	// Fetch session to check ownership
	s, err := session.SessionByID(sessionID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Session not found")
		return
	}

	if s.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "You cannot revoke someone else's session")
		return
	}

	// Check if it's the current session
	authHeader := r.Header.Get("Authorization")
	currentToken := utils.ExtractBearerToken(authHeader)
	if s.AccessToken == currentToken {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "You cannot revoke your current session from this endpoint. Use logout instead.")
		return
	}

	if err := session.DeactivateSessionByID(sessionID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Session revoked"}, http.StatusOK)
}
