package account

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListTrustedDevices godoc
// @Summary List trusted devices
// @Description Returns all trusted devices for the authenticated user (devices that bypass MFA).
// @Tags account-security
// @Produce json
// @Security UserAuth
// @Success 200 {array} TrustedDeviceResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/trusted-devices [get]
func HandleListTrustedDevices(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	devices, err := trusteddevice.TrustedDevicesByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []TrustedDeviceResponse
	for _, d := range devices {
		response = append(response, TrustedDeviceResponse{
			ID:         d.ID,
			DeviceName: d.DeviceName,
			CreatedAt:  d.CreatedAt,
			LastUsedAt: d.LastUsedAt,
			ExpiresAt:  d.ExpiresAt,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleRevokeTrustedDevice godoc
// @Summary Revoke a trusted device
// @Description Removes a trusted device so it will require MFA again on next login.
// @Tags account-security
// @Produce json
// @Param id path string true "Trusted device ID"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError
// @Router /account/api/trusted-devices/{id} [delete]
func HandleRevokeTrustedDevice(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing device ID")
		return
	}

	device, err := trusteddevice.TrustedDeviceByID(deviceID)
	if err != nil || device.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Device not found or not owned by you")
		return
	}

	if err := trusteddevice.DeleteTrustedDevice(deviceID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Trusted device revoked"}, http.StatusOK)
}
