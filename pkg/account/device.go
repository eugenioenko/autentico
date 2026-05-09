package account

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/devicecode"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type DeviceVerifyRequest struct {
	UserCode string `json:"user_code"`
}

type DeviceVerifyResponse struct {
	UserCode   string `json:"user_code"`
	ClientName string `json:"client_name"`
	Scope      string `json:"scope"`
}

// HandleDeviceVerify looks up a device code by user_code and returns the client info.
func HandleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	usr := middleware.UserFromContext(r.Context())
	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var req DeviceVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	userCode := devicecode.NormalizeUserCode(req.UserCode)
	if userCode == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "user_code is required")
		return
	}

	dc, err := devicecode.DeviceCodeByUserCode(userCode)
	if err != nil || dc == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Invalid or unknown code")
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusGone, "expired", "This code has expired")
		return
	}

	if dc.Status != "pending" {
		utils.WriteErrorResponse(w, http.StatusConflict, "already_used", "This code has already been used")
		return
	}

	clientName := dc.ClientID
	if registeredClient, err := client.ClientByClientID(dc.ClientID); err == nil && registeredClient != nil {
		clientName = registeredClient.ClientName
	}

	utils.WriteApiResponse(w, DeviceVerifyResponse{
		UserCode:   devicecode.FormatUserCode(userCode),
		ClientName: clientName,
		Scope:      dc.Scope,
	}, http.StatusOK)
}

// HandleDeviceAuthorize authorizes a pending device code for the current user.
func HandleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	usr := middleware.UserFromContext(r.Context())
	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var req DeviceVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	userCode := devicecode.NormalizeUserCode(req.UserCode)
	if userCode == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "user_code is required")
		return
	}

	dc, err := devicecode.DeviceCodeByUserCode(userCode)
	if err != nil || dc == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Invalid or unknown code")
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusGone, "expired", "This code has expired")
		return
	}

	if dc.Status != "pending" {
		utils.WriteErrorResponse(w, http.StatusConflict, "already_used", "This code has already been used")
		return
	}

	if err := devicecode.AuthorizeDeviceCode(userCode, usr.ID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to authorize device")
		return
	}

	utils.WriteApiResponse(w, map[string]string{"status": "authorized"}, http.StatusOK)
}

// HandleDeviceDeny denies a pending device code.
func HandleDeviceDeny(w http.ResponseWriter, r *http.Request) {
	usr := middleware.UserFromContext(r.Context())
	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var req DeviceVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	userCode := devicecode.NormalizeUserCode(req.UserCode)
	if userCode == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "user_code is required")
		return
	}

	dc, err := devicecode.DeviceCodeByUserCode(userCode)
	if err != nil || dc == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Invalid or unknown code")
		return
	}

	if dc.Status != "pending" {
		utils.WriteErrorResponse(w, http.StatusConflict, "already_used", "This code has already been used")
		return
	}

	if err := devicecode.DenyDeviceCode(userCode); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to deny device")
		return
	}

	utils.WriteApiResponse(w, map[string]string{"status": "denied"}, http.StatusOK)
}
