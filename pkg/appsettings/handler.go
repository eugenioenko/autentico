package appsettings

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleOnboarding is a public endpoint that returns the current onboarding status.
// GET /admin/api/onboarding → {"onboarded": bool}
func HandleOnboarding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}
	onboarded := IsOnboarded()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"onboarded": onboarded})
}

// HandleSettings is an admin-protected endpoint for reading and updating settings.
// GET  /admin/api/settings → returns all settings as a JSON object
// PUT  /admin/api/settings → accepts a JSON object and updates matching keys
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(all)
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
