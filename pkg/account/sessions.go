package account

import (
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// currentIdpSessionID returns the IdP session ID of the browser issuing this
// account-api request, or "" if no IdP session cookie is present. The cookie
// is Path=/ so it reaches /account directly — no access-token-to-session
// fallback needed.
func currentIdpSessionID(r *http.Request) string {
	return idpsession.ReadCookie(r)
}

// HandleListSessions godoc
// @Summary List current user's active devices (IdP sessions)
// @Description Returns paginated live IdP (SSO) sessions for the authenticated user — one row per browser/device signed in.
// @Description `active_apps_count` is the number of non-deactivated OAuth sessions born from that IdP session.
// @Description `is_current` marks the row matching the request's IdP session cookie.
// @Tags account-security
// @Produce json
// @Param limit query integer false "Max results per page (1–100)" default(100)
// @Param offset query integer false "Number of results to skip" default(0)
// @Security UserAuth
// @Success 200 {object} model.ListResponse[SessionResponse]
// @Failure 401 {object} model.ApiError
// @Router /account/api/sessions [get]
func HandleListSessions(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	params := api.ParseListParams(r)
	if params.Order == "" {
		params.Order = "desc"
	}
	currentID := currentIdpSessionID(r)

	idleCutoff := time.Time{}
	if idle := config.Get().AuthSsoSessionIdleTimeout; idle > 0 {
		idleCutoff = time.Now().Add(-idle)
	}

	devices, total, err := idpsession.ListActiveDevicesForUserPaginated(usr.ID, idleCutoff, params)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	items := make([]SessionResponse, 0, len(devices))
	for _, d := range devices {
		items = append(items, SessionResponse{
			ID:              d.ID,
			UserAgent:       d.UserAgent,
			IPAddress:       d.IPAddress,
			LastActivityAt:  d.LastActivityAt,
			CreatedAt:       d.CreatedAt,
			ActiveAppsCount: d.ActiveAppsCount,
			IsCurrent:       d.ID == currentID,
		})
	}

	utils.SuccessResponse(w, model.ListResponse[SessionResponse]{
		Items: items,
		Total: total,
	}, http.StatusOK)
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

// HandleRevokeOtherSessions godoc
// @Summary Revoke all sessions except the current one
// @Description Revokes all tokens, OAuth sessions, and IdP sessions for the authenticated user, keeping only the session that issued this request alive.
// @Tags account-security
// @Produce json
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /account/api/sessions/revoke-others [post]
func HandleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	v, err := bearer.ValidateBearer(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	if err := user.RevokeOtherUserAccess(v.Session.UserID, v.Token); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "All other sessions revoked"}, http.StatusOK)
}
