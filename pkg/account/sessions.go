package account

import (
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// currentIdpSessionID resolves the "current device" for an account-api request.
// The IdP session cookie is scoped to /oauth2 so /account never sees it —
// instead we look up the access token's sessions row and read its
// idp_session_id. Falls back to the cookie if the request somehow carries one
// (e.g. a server-side caller that ignores path scoping).
func currentIdpSessionID(r *http.Request) string {
	if cookie := idpsession.ReadCookie(r); cookie != "" {
		return cookie
	}
	token := utils.ExtractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		return ""
	}
	var idp *string
	_ = db.GetDB().QueryRow(
		`SELECT idp_session_id FROM sessions WHERE access_token = ?`, token,
	).Scan(&idp)
	if idp == nil {
		return ""
	}
	return *idp
}

// HandleListSessions godoc
// @Summary List current user's active devices (IdP sessions)
// @Description Returns all live IdP (SSO) sessions for the authenticated user — one row per browser/device signed in.
// @Description `active_apps_count` is the number of non-deactivated OAuth sessions born from that IdP session.
// @Description `is_current` marks the row matching the request's IdP session cookie.
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

	currentID := currentIdpSessionID(r)

	// Filter idle-expired rows in the query itself so the list stays consistent
	// with /authorize's lazy idle check (pkg/authorize/handler.go:141), even when
	// the cleanup sweep hasn't yet flipped deactivated_at. Defence-in-depth with
	// pkg/cleanup's idle UPDATE.
	idleCutoff := time.Time{}
	if idle := config.Get().AuthSsoSessionIdleTimeout; idle > 0 {
		idleCutoff = time.Now().Add(-idle)
	}

	rows, err := db.GetDB().Query(`
		SELECT s.id, s.user_agent, s.ip_address, s.last_activity_at, s.created_at,
		       (SELECT COUNT(*) FROM sessions
		          WHERE idp_session_id = s.id AND deactivated_at IS NULL) AS active_apps_count
		  FROM idp_sessions s
		 WHERE s.user_id = ?
		   AND s.deactivated_at IS NULL
		   AND (? = '' OR s.last_activity_at > ?)
		 ORDER BY s.last_activity_at DESC`,
		usr.ID, idleCutoff, idleCutoff,
	)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	defer func() { _ = rows.Close() }()

	response := []SessionResponse{}
	for rows.Next() {
		var s SessionResponse
		var userAgent, ipAddress *string
		if err := rows.Scan(&s.ID, &userAgent, &ipAddress, &s.LastActivityAt, &s.CreatedAt, &s.ActiveAppsCount); err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		if userAgent != nil {
			s.UserAgent = *userAgent
		}
		if ipAddress != nil {
			s.IPAddress = *ipAddress
		}
		s.IsCurrent = s.ID == currentID
		response = append(response, s)
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleRevokeSession godoc
// @Summary Revoke one of the authenticated user's devices
// @Description Cascade-revokes an IdP session: deactivates the idp_session row, deactivates every child OAuth session, and revokes every child access/refresh token.
// @Description Revoking the current device also clears the IdP session cookie — the UI is expected to redirect the user through /oauth2/logout.
// @Tags account-security
// @Produce json
// @Param id path string true "IdP session ID"
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

	targetID := r.PathValue("id")
	if targetID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing session ID")
		return
	}

	// Ownership: only the subject of the IdP session can revoke it. No
	// admin-side bypass here — admin force-logout has its own dedicated endpoint.
	sess, err := idpsession.IdpSessionByID(targetID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Session not found")
		return
	}
	if sess.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "You cannot revoke someone else's session")
		return
	}

	if err := idpsession.DeactivateWithCascade(targetID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// If the user revoked the device they're currently using, clear the browser
	// cookie so /authorize won't try to resurrect an already-deactivated session.
	// The account UI is expected to redirect to /oauth2/logout after a 200 to
	// complete the sign-out UX.
	if currentIdpSessionID(r) == targetID {
		idpsession.ClearCookie(w)
	}

	utils.SuccessResponse(w, map[string]string{"message": "Session revoked"}, http.StatusOK)
}
