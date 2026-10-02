package account

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type AppResponse struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	OpenURL    string `json:"open_url,omitempty"`
}

// HandleListApps returns the active, user-facing clients available to sign in to.
// @Summary List available applications
// @Description Returns active clients, excluding Autentico's internal clients.
// @Tags account
// @Produce json
// @Security UserAuth
// @Success 200 {array} AppResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/apps [get]
func HandleListApps(w http.ResponseWriter, r *http.Request) {
	if middleware.UserFromContext(r.Context()) == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	rows, err := db.GetDB().Query(`
		SELECT client_id, client_name, redirect_uris FROM clients
		WHERE is_active = TRUE AND client_id NOT IN (?, ?)
		ORDER BY client_name COLLATE NOCASE, client_id
	`, config.AdminClientID, config.AccountClientID)
	if err != nil {
		slog.Error("account: failed to list apps", "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list applications")
		return
	}
	defer func() { _ = rows.Close() }()

	apps := make([]AppResponse, 0)
	for rows.Next() {
		var app AppResponse
		var redirectURIs string
		if err := rows.Scan(&app.ClientID, &app.ClientName, &redirectURIs); err != nil {
			slog.Error("account: failed to read app", "error", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list applications")
			return
		}
		app.OpenURL = appOrigin(redirectURIs)
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		slog.Error("account: failed to finish listing apps", "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list applications")
		return
	}

	utils.SuccessResponse(w, apps, http.StatusOK)
}

// appOrigin uses a registered callback only to find the app's site. Never
// expose a callback URL as the Open link because visiting one directly can fail.
func appOrigin(rawRedirectURIs string) string {
	var redirectURIs []string
	if err := json.Unmarshal([]byte(rawRedirectURIs), &redirectURIs); err != nil {
		return ""
	}
	for _, redirectURI := range redirectURIs {
		u, err := url.Parse(redirectURI)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(redirectURI, "\r\n") {
			continue
		}
		if u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			return u.Scheme + "://" + u.Host + "/"
		}
	}
	return ""
}
