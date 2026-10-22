package devicecode

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/utils"
)

const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// HandleDeviceAuthorization handles the device authorization request.
// @Summary Device Authorization
// @Description Issues device/user codes. Public clients identify themselves; confidential clients authenticate with HTTP Basic or form credentials (RFC 8628).
// @Tags oauth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param client_id formData string false "Client ID (required unless using HTTP Basic authentication)"
// @Param client_secret formData string false "Confidential client secret for form authentication"
// @Param scope formData string false "Requested scope"
// @Success 200 {object} DeviceAuthorizationResponse
// @Failure 400 {object} model.AuthErrorResponse
// @Failure 401 {object} model.AuthErrorResponse "Invalid HTTP Basic client authentication"
// @Router /oauth2/device_authorization [post]
func HandleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	// RFC 8628 §3.1: the client makes an HTTP POST request to the device authorization endpoint
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only POST method is allowed")
		return
	}

	// RFC 8628 §3.1: parameters use application/x-www-form-urlencoded
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	scope := r.FormValue("scope")

	// RFC 6749 §5.2: classify Basic failures by the attempted scheme,
	// including malformed headers rejected by the shared authenticator.
	authorization := strings.Fields(r.Header.Get("Authorization"))
	basicAuth := len(authorization) > 0 && strings.EqualFold(authorization[0], "Basic")

	// RFC 8628 §3.1: confidential clients authenticate as at the token
	// endpoint; public clients identify themselves with client_id.
	registeredClient, err := client.AuthenticateClientFromRequest(r)
	if err != nil {
		// RFC 6749 §5.2: malformed or multiple credentials are invalid_request.
		if errors.Is(err, client.ErrInvalidClientAuthenticationRequest) {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		status := http.StatusBadRequest
		// RFC 6749 §5.2: header-based authentication failures require a
		// 401 response and a challenge matching the attempted scheme.
		if basicAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="device_authorization"`)
			status = http.StatusUnauthorized
		}
		slog.Warn("device_authorization: client authentication failed", "request_id", reqid.Get(r.Context()))
		utils.WriteErrorResponse(w, status, "invalid_client", "Client authentication failed")
		return
	}
	// RFC 8628 §3.1: client_id is required when not authenticating.
	if registeredClient == nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	clientID := registeredClient.ClientID

	// RFC 8628 §3.2 / RFC 6749 §5.2: unauthorized_client when the client may not use this grant
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

	// RFC 8628 §3.2 / RFC 6749 §5.1: response MUST NOT be cached
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	utils.WriteApiResponse(w, resp, http.StatusOK)
}
