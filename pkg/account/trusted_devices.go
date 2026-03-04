package account

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func HandleListTrustedDevices(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
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

func HandleRevokeTrustedDevice(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
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
