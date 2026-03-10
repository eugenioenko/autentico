package appsettings

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleGetSettings godoc
// @Summary Get system settings
// @Description Retrieve all system settings (except sensitive values).
// @Tags admin
// @Produce json
// @Security BearerAuth
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
// @Tags admin
// @Accept json
// @Security BearerAuth
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

	for k, v := range updates {
		if err := SetSetting(k, v); err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to update settings")
			return
		}
	}

	_ = LoadIntoConfig()

	w.WriteHeader(http.StatusNoContent)
}
