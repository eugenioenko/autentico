package devicecode

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/utils"
)

const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// HandleDeviceAuthorization handles the device authorization request.
// @Summary Device Authorization
// @Description Issues a device code and user code for device authorization flow (RFC 8628)
// @Tags oauth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param client_id formData string true "Client ID"
// @Param scope formData string false "Requested scope"
// @Success 200 {object} DeviceAuthorizationResponse
// @Failure 400 {object} model.AuthErrorResponse
// @Router /oauth2/device_authorization [post]
func HandleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only POST method is allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	// RFC 8628 §3.1: client_id is REQUIRED in the device authorization request
	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	if clientID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	// RFC 8628 §3.1: validate client exists and supports device_code grant
	registeredClient, err := client.ClientByClientID(clientID)
	if err != nil {
		slog.Warn("device_authorization: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", clientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
		return
	}

	if !client.IsGrantTypeAllowed(registeredClient, DeviceCodeGrantType) {
		slog.Warn("device_authorization: grant type not allowed", "request_id", reqid.Get(r.Context()), "client_id", clientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "unauthorized_client", "Client is not authorized for device_code grant")
		return
	}

	// RFC 8628 §3.1: scope is OPTIONAL; validate against client's allowed scopes
	if scope != "" && !client.ValidateScopes(registeredClient, scope) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "One or more requested scopes are not allowed for this client")
		return
	}
	if scope == "" && registeredClient.Scopes != "" {
		scope = registeredClient.Scopes
	}

	deviceCode, err := GenerateDeviceCode()
	if err != nil {
		slog.Error("device_authorization: failed to generate device_code", "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate device code")
		return
	}

	userCode, err := GenerateUserCode()
	if err != nil {
		slog.Error("device_authorization: failed to generate user_code", "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate user code")
		return
	}

	cfg := config.Get()
	dc := DeviceCode{
		Code:            deviceCode,
		UserCode:        userCode,
		ClientID:        clientID,
		Scope:           scope,
		ExpiresAt:       time.Now().Add(cfg.DeviceCodeExpiration),
		IntervalSeconds: cfg.DeviceCodePollingInterval,
		Status:          "pending",
	}

	if err := CreateDeviceCode(dc); err != nil {
		slog.Error("device_authorization: failed to store device code", "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create device code")
		return
	}

	bs := config.GetBootstrap()
	verificationURI := fmt.Sprintf("%s/account/device", bs.AppURL)

	// RFC 8628 §3.2: response MUST include device_code, user_code, verification_uri, expires_in
	resp := DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                FormatUserCode(userCode),
		VerificationURI:         verificationURI,
		VerificationURIComplete: fmt.Sprintf("%s/%s", verificationURI, FormatUserCode(userCode)),
		ExpiresIn:               int(cfg.DeviceCodeExpiration.Seconds()),
		Interval:                cfg.DeviceCodePollingInterval,
	}

	// RFC 8628 §3.2: response MUST NOT be cached
	w.Header().Set("Cache-Control", "no-store")
	utils.WriteApiResponse(w, resp, http.StatusOK)
}

