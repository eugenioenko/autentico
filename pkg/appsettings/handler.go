package appsettings

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// durationSettings lists keys whose values must parse as Go durations
// (time.ParseDuration). Values in the slice are non-duration strings that
// are also accepted — e.g. "0" and "-1" on audit_log_retention mean
// "disabled" and "keep forever" respectively.
var durationSettings = map[string][]string{
	"access_token_expiration":       nil,
	"refresh_token_expiration":      nil,
	"authorization_code_expiration": nil,
	"sso_session_idle_timeout":      {"", "0"},
	"account_lockout_duration":      nil,
	"trust_device_expiration":       nil,
	"cleanup_interval":              nil,
	"cleanup_retention":             nil,
	"email_verification_expiration": nil,
	"password_reset_expiration":     nil,
	"audit_log_retention":           {"", "0", "-1"},
}

// validateDurationSettings returns an error if any duration-typed setting
// in updates has a value that neither parses as a Go duration nor matches
// one of its allowed special values.
func validateDurationSettings(updates map[string]string) error {
	for k, allowed := range durationSettings {
		v, ok := updates[k]
		if !ok {
			continue
		}
		if slices.Contains(allowed, v) {
			continue
		}
		if _, err := time.ParseDuration(v); err != nil {
			return fmt.Errorf("setting %q has invalid duration %q (expected a Go duration like 15m, 1h, 24h)", k, v)
		}
	}
	return nil
}

// HandleGetSettings godoc
// @Summary Get system settings
// @Description Retrieve all system settings (except sensitive values).
// @Tags admin-settings
// @Produce json
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Router /admin/api/settings [get]
func HandleGetSettings(w http.ResponseWriter, _ *http.Request) {
	all, err := GetAllSettings()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to read settings")
		return
	}
	delete(all, "private_key")
	delete(all, "smtp_password")

	utils.SuccessResponse(w, all, http.StatusOK)
}

// HandlePutSettings godoc
// @Summary Update system settings
// @Description Update multiple settings by key-value pairs.
// @Tags admin-settings
// @Accept json
// @Security AdminAuth
// @Success 204
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/settings [put]
func HandlePutSettings(w http.ResponseWriter, r *http.Request) {
	var updates map[string]string
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	protected := map[string]bool{"onboarded": true, "private_key": true}
	for k := range updates {
		if protected[k] {
			delete(updates, k)
		}
	}

	if err := validateDurationSettings(updates); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	for k, v := range updates {
		if err := SetSetting(k, v); err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to update settings")
			return
		}
	}

	_ = LoadIntoConfig()

	audit.Log(audit.EventSettingsUpdated, audit.ActorFromRequest(r), audit.TargetSettings, "", nil, utils.GetClientIP(r))

	w.WriteHeader(http.StatusNoContent)
}

// settingsExport is the JSON envelope for exported settings.
type settingsExport struct {
	Version    int               `json:"version"`
	ExportedAt time.Time         `json:"exported_at"`
	Settings   map[string]string `json:"settings"`
}

// settingsPreviewRow is one row in the import preview table.
type settingsPreviewRow struct {
	Key      string `json:"key"`
	Current  string `json:"current"`
	Incoming string `json:"incoming"`
}

// settingsPreviewResponse is the response from the import preview endpoint.
type settingsPreviewResponse struct {
	Rows    []settingsPreviewRow `json:"rows"`
	Unknown []string             `json:"unknown"`
}

// HandleExportSettings godoc
// @Summary Export settings
// @Description Export all settings as a JSON file (smtp_password excluded).
// @Tags admin-settings
// @Produce json
// @Security AdminAuth
// @Success 200 {object} settingsExport
// @Router /admin/api/settings/export [get]
func HandleExportSettings(w http.ResponseWriter, _ *http.Request) {
	all, err := GetAllSettings()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to read settings")
		return
	}
	delete(all, "onboarded")
	export := settingsExport{
		Version:    1,
		ExportedAt: time.Now().UTC(),
		Settings:   all,
	}
	utils.SuccessResponse(w, export, http.StatusOK)
}

// HandleImportPreview godoc
// @Summary Preview settings import
// @Description Returns a diff of current vs incoming values for all known keys, plus unknown keys.
// @Tags admin-settings
// @Accept json
// @Produce json
// @Security AdminAuth
// @Success 200 {object} settingsPreviewResponse
// @Router /admin/api/settings/import/preview [post]
func HandleImportPreview(w http.ResponseWriter, r *http.Request) {
	var payload settingsExport
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	current, err := GetAllSettings()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to read current settings")
		return
	}

	rows := []settingsPreviewRow{}
	unknown := []string{}

	for k, incoming := range payload.Settings {
		if _, known := defaults[k]; !known {
			unknown = append(unknown, k)
			continue
		}
		rows = append(rows, settingsPreviewRow{
			Key:      k,
			Current:  current[k],
			Incoming: incoming,
		})
	}

	utils.SuccessResponse(w, settingsPreviewResponse{Rows: rows, Unknown: unknown}, http.StatusOK)
}

// HandleImportApply godoc
// @Summary Apply settings import
// @Description Applies imported settings, skipping unknown keys and protected fields.
// @Tags admin-settings
// @Accept json
// @Produce json
// @Security AdminAuth
// @Success 204
// @Router /admin/api/settings/import/apply [post]
func HandleImportApply(w http.ResponseWriter, r *http.Request) {
	var payload settingsExport
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	protected := map[string]bool{"onboarded": true, "private_key": true}

	if err := validateDurationSettings(payload.Settings); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	for k, v := range payload.Settings {
		if protected[k] {
			continue
		}
		if _, known := defaults[k]; !known {
			continue
		}
		if err := SetSetting(k, v); err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to apply settings")
			return
		}
	}

	_ = LoadIntoConfig()
	audit.Log(audit.EventSettingsImported, audit.ActorFromRequest(r), audit.TargetSettings, "", nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// HandleTestSmtp godoc
// @Summary Test SMTP configuration
// @Description Sends a test email to the currently authenticated admin's registered email address.
// @Tags admin-settings
// @Produce json
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/settings/test-smtp [post]
func HandleTestSmtp(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	if usr.Email == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "no_email", "Admin account has no registered email address. Add an email to your profile before testing SMTP.")
		return
	}

	if err := mfa.SendTestEmail(usr.Email); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "smtp_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Test email sent to " + usr.Email}, http.StatusOK)
}
