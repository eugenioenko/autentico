package forwardauth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleList godoc
// @Summary List protected applications
// @Tags admin-forward-auth
// @Produce json
// @Security AdminAuth
// @Success 200 {object} model.ApiResponse[[]App]
// @Router /admin/api/protected-apps [get]
func HandleList(w http.ResponseWriter, r *http.Request) {
	apps, err := ListApps()
	if err != nil {
		deny(w, 503)
		return
	}
	utils.WriteApiResponse(w, model.ApiResponse[[]App]{Data: apps}, 200)
}

// HandleSave godoc
// @Summary Create or replace a protected application
// @Description Exact HTTPS origins on same-site or unrelated domains are supported; HTTP is limited to loopback. Production app hostnames must differ from the IdP hostname. Origin is immutable and must be supplied unchanged on replacement. Updates replace name, paths and TTL; omitted is_active preserves its value. Disabling revokes all app sessions.
// @Tags admin-forward-auth
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param id path string false "Application ID for replacement"
// @Param request body AppRequest true "Application configuration"
// @Success 200 {object} model.ApiResponse[App]
// @Success 201 {object} model.ApiResponse[App]
// @Failure 400 {object} model.AuthErrorResponse
// @Router /admin/api/protected-apps [post]
// @Router /admin/api/protected-apps/{id} [put]
func HandleSave(w http.ResponseWriter, r *http.Request) {
	var req AppRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.Decode(&struct{}{}) != io.EOF {
		utils.WriteErrorResponse(w, 400, "invalid_request", "Invalid application configuration")
		return
	}
	if err := validate(&req); err != nil {
		utils.WriteErrorResponse(w, 400, "invalid_request", err.Error())
		return
	}
	id := r.PathValue("id")
	a, err := SaveApp(id, req)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			deny(w, 404)
		} else if errors.Is(err, errImmutableOrigin) {
			utils.WriteErrorResponse(w, 400, "invalid_request", err.Error())
		} else if strings.Contains(err.Error(), "UNIQUE constraint") {
			utils.WriteErrorResponse(w, 400, "invalid_request", "An application with that origin already exists")
		} else {
			slog.Error("forwardauth: unable to save application", "app_id", id, "error", err)
			deny(w, 503)
		}
		return
	}
	status := 200
	if id == "" {
		status = 201
	}
	event := audit.EventProtectedAppUpdated
	if id == "" {
		event = audit.EventProtectedAppCreated
	}
	audit.Log(event, audit.ActorFromRequest(r), audit.TargetProtectedApp, a.ID, audit.Detail("name", a.Name, "is_active", strconv.FormatBool(a.IsActive)), utils.GetClientIP(r))
	utils.WriteApiResponse(w, model.ApiResponse[*App]{Data: a}, status)
}

// HandleDelete godoc
// @Summary Delete a protected application and revoke its sessions
// @Tags admin-forward-auth
// @Security AdminAuth
// @Param id path string true "Application ID"
// @Success 204 "Deleted"
// @Failure 404 "Unknown application"
// @Router /admin/api/protected-apps/{id} [delete]
func HandleDelete(w http.ResponseWriter, r *http.Request) {
	if err := DeleteApp(r.PathValue("id")); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			deny(w, 404)
		} else {
			deny(w, 503)
		}
		return
	}
	audit.Log(audit.EventProtectedAppDeleted, audit.ActorFromRequest(r), audit.TargetProtectedApp, r.PathValue("id"), nil, utils.GetClientIP(r))
	w.WriteHeader(204)
}
