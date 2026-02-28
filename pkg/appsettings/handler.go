package appsettings

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleOnboarding is a public endpoint that returns the current onboarding status.
// GET /admin/api/onboarding → {"onboarded": bool}
// @Summary Check onboarding status
// @Description Returns whether the system has been initialized with an admin account and the current OAuth path.
// @Tags onboarding
// @Produce json
// @Success 200 {object} map[string]any
// @Router /admin/api/onboarding [get]
func HandleOnboarding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}
	onboarded := IsOnboarded()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"onboarded":  onboarded,
		"oauth_path": config.GetBootstrap().AppOAuthPath,
	})
}

// HandleSettings is an admin-protected endpoint for reading and updating settings.
// GET  /admin/api/settings → returns all settings as a JSON object
// PUT  /admin/api/settings → accepts a JSON object and updates matching keys
// @Summary System settings
// @Description GET: Retrieve all system settings (except sensitive values). PUT: Update multiple settings.
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "All settings (GET)"
// @Success 204 "Settings updated (PUT)"
// @Router /admin/api/settings [get]
// @Router /admin/api/settings [put]
func HandleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleGetSettings(w, r)
	case http.MethodPut:
		handlePutSettings(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

func handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	all, err := GetAllSettings()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to read settings")
		return
	}
	// Omit sensitive keys from the response
	delete(all, "private_key")
	delete(all, "smtp_password")

	utils.SuccessResponse(w, all, http.StatusOK)
}

func handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var updates map[string]string
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	// Reject attempts to set protected keys via this endpoint
	protected := map[string]bool{"onboarded": true, "private_key": true}
	for k := range updates {
		if protected[k] {
			delete(updates, k)
		}
	}

	for k, v := range updates {
		if err := SetSetting(k, v); err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to update settings")
			return
		}
	}

	// Reload config from DB so changes take effect immediately
	_ = LoadIntoConfig()

	w.WriteHeader(http.StatusNoContent)
}
