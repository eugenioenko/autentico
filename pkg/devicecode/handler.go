package devicecode

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

// getAuthenticatedUserID extracts the currently logged-in user from the IdP session cookie.
func getAuthenticatedUserID(r *http.Request) string {
	sessionID := idpsession.ReadCookie(r)
	if sessionID == "" {
		return ""
	}
	sess, err := idpsession.IdpSessionByID(sessionID)
	if err != nil || sess == nil {
		return ""
	}
	return sess.UserID
}

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
	verificationURI := fmt.Sprintf("%s%s/device", bs.AppURL, bs.AppOAuthPath)

	// RFC 8628 §3.2: response MUST include device_code, user_code, verification_uri, expires_in
	resp := DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                FormatUserCode(userCode),
		VerificationURI:         verificationURI,
		VerificationURIComplete: fmt.Sprintf("%s?user_code=%s", verificationURI, FormatUserCode(userCode)),
		ExpiresIn:               int(cfg.DeviceCodeExpiration.Seconds()),
		Interval:                cfg.DeviceCodePollingInterval,
	}

	// RFC 8628 §3.2: response MUST NOT be cached
	w.Header().Set("Cache-Control", "no-store")
	utils.WriteApiResponse(w, resp, http.StatusOK)
}

// HandleDeviceVerification renders the device verification page and handles form submission.
func HandleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleDeviceVerifyGet(w, r)
	case http.MethodPost:
		handleDeviceVerifyPost(w, r)
	default:
		view.RenderError(w, r, http.StatusMethodNotAllowed, "Method not allowed.")
	}
}

func handleDeviceVerifyGet(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	renderDeviceVerifyPage(w, r, userCode, "")
}

func handleDeviceVerifyPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderDeviceVerifyPage(w, r, "", "Invalid form data")
		return
	}

	action := r.FormValue("action")
	userCode := NormalizeUserCode(r.FormValue("user_code"))

	// Check if user is authenticated via IdP session
	userID := getAuthenticatedUserID(r)
	if userID == "" {
		// Not authenticated — redirect to login with return URL
		bs := config.GetBootstrap()
		returnURL := fmt.Sprintf("%s%s/device?user_code=%s", bs.AppURL, bs.AppOAuthPath, FormatUserCode(userCode))
		loginURL := fmt.Sprintf("%s%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&prompt=login&device_return=%s",
			bs.AppURL, bs.AppOAuthPath, config.AdminClientID, bs.AppURL, returnURL)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Lookup the device code
	dc, err := DeviceCodeByUserCode(userCode)
	if err != nil || dc == nil {
		renderDeviceVerifyPage(w, r, "", "Invalid or expired code. Please check and try again.")
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		renderDeviceVerifyPage(w, r, "", "This code has expired. Please request a new one from your device.")
		return
	}

	if dc.Status != "pending" {
		renderDeviceVerifyPage(w, r, "", "This code has already been used.")
		return
	}

	// If no action yet, show the confirmation page
	if action == "" || action == "verify" {
		registeredClient, _ := client.ClientByClientID(dc.ClientID)
		clientName := dc.ClientID
		if registeredClient != nil {
			clientName = registeredClient.ClientName
		}
		renderDeviceConfirmPage(w, r, userCode, clientName, dc.Scope)
		return
	}

	// Handle authorize/deny
	switch action {
	case "allow":
		if err := AuthorizeDeviceCode(userCode, userID); err != nil {
			slog.Error("device_verify: failed to authorize", "error", err)
			renderDeviceVerifyPage(w, r, "", "Something went wrong. Please try again.")
			return
		}
		renderDeviceSuccessPage(w, r)
	case "deny":
		if err := DenyDeviceCode(userCode); err != nil {
			slog.Error("device_verify: failed to deny", "error", err)
			renderDeviceVerifyPage(w, r, "", "Something went wrong. Please try again.")
			return
		}
		renderDeviceDeniedPage(w, r)
	default:
		renderDeviceVerifyPage(w, r, userCode, "Invalid action.")
	}
}

func renderDeviceVerifyPage(w http.ResponseWriter, r *http.Request, userCode string, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("device_verify")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"UserCode":     FormatUserCode(NormalizeUserCode(userCode)),
		"Error":        errMsg,
		"ThemeTitle":   cfg.Theme.Title,
		"ThemeLogoUrl": cfg.Theme.LogoUrl,
		csrf.TemplateTag: csrf.TemplateField(r),
	}
	view.InjectNonce(r, data)
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

func renderDeviceConfirmPage(w http.ResponseWriter, r *http.Request, userCode string, clientName string, scope string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("device_confirm")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"UserCode":     FormatUserCode(userCode),
		"ClientName":   clientName,
		"Scope":        scope,
		"ThemeTitle":   cfg.Theme.Title,
		"ThemeLogoUrl": cfg.Theme.LogoUrl,
		csrf.TemplateTag: csrf.TemplateField(r),
	}
	view.InjectNonce(r, data)
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

func renderDeviceSuccessPage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("device_success")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"ThemeTitle":   cfg.Theme.Title,
		"ThemeLogoUrl": cfg.Theme.LogoUrl,
	}
	view.InjectNonce(r, data)
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

func renderDeviceDeniedPage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("device_denied")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"ThemeTitle":   cfg.Theme.Title,
		"ThemeLogoUrl": cfg.Theme.LogoUrl,
	}
	view.InjectNonce(r, data)
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
