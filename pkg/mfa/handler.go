package mfa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
	qrcode "github.com/skip2/go-qrcode"
)

// HandleMfa handles multi-factor authentication requests.
// @Summary Multi-factor authentication
// @Description Renders the MFA verification or enrollment page (GET) or processes the MFA code (POST).
// @Tags mfa
// @Accept x-www-form-urlencoded
// @Produce html
// @Param challenge_id query string false "MFA challenge ID (GET)"
// @Param challenge_id formData string false "MFA challenge ID (POST)"
// @Param code formData string false "Verification code (POST)"
// @Param totp_secret formData string false "TOTP secret for enrollment (POST)"
// @Param trust_device formData string false "Whether to trust the device (POST)"
// @Success 200 {string} string "MFA form (GET)"
// @Success 302 {string} string "Redirect back to client with code after success (POST)"
// @Router /oauth2/mfa [get]
// @Router /oauth2/mfa [post]
func HandleMfa(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleMfaGet(w, r)
	case http.MethodPost:
		handleMfaPost(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

func handleMfaGet(w http.ResponseWriter, r *http.Request) {
	challengeID := r.URL.Query().Get("challenge_id")
	if challengeID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing challenge_id")
		return
	}

	challenge, err := MfaChallengeByID(challengeID)
	if err != nil {
		redirectToLoginWithError(w, r, nil, "Verification session not found. Please log in again.")
		return
	}

	if challenge.Used || time.Now().After(challenge.ExpiresAt) {
		redirectToLoginWithError(w, r, challenge, "Verification session has expired. Please log in again.")
		return
	}

	cfg := config.Get()

	if challenge.Method == "totp" {
		usr, err := user.UserByID(challenge.UserID)
		if err != nil {
			slog.Error("mfa: failed to get user for TOTP challenge", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get user")
			return
		}

		if !usr.TotpVerified {
			renderEnrollPage(w, r, challenge, usr, cfg, "")
			return
		}
	}

	if challenge.Method == "email" {
		usr, err := user.UserByID(challenge.UserID)
		if err != nil {
			slog.Error("mfa: failed to get user for email OTP challenge", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get user")
			return
		}
		otp, err := GenerateEmailOTP()
		if err != nil {
			slog.Error("mfa: failed to generate email OTP", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate OTP")
			return
		}
		hashedOTP := utils.HashSHA256(otp)
		challenge.Code = hashedOTP
		_ = UpdateChallengeCode(challenge.ID, hashedOTP)
		if err := SendEmailOTP(usr.Email, otp); err != nil {
			slog.Error("mfa: failed to send verification email", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to send verification email")
			return
		}
	}

	renderVerifyPage(w, r, challenge, cfg, "")
}

func handleMfaPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	challengeID := r.FormValue("challenge_id")
	code := r.FormValue("code")
	totpSecret := r.FormValue("totp_secret")

	if challengeID == "" || code == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing required fields")
		return
	}

	challenge, err := MfaChallengeByID(challengeID)
	if err != nil {
		redirectToLoginWithError(w, r, nil, "Verification session not found. Please log in again.")
		return
	}

	if challenge.Used || time.Now().After(challenge.ExpiresAt) {
		redirectToLoginWithError(w, r, challenge, "Verification session has expired. Please log in again.")
		return
	}

	cfg := config.Get()

	usr, err := user.UserByID(challenge.UserID)
	if err != nil {
		slog.Error("mfa: failed to get user for verification", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get user")
		return
	}

	switch challenge.Method {
	case "totp":
		if !usr.TotpVerified {
			// Enrollment flow: validate against the secret from the form
			if totpSecret == "" {
				renderEnrollPage(w, r, challenge, usr, cfg, "Missing TOTP secret")
				return
			}
			if !ValidateTotpCode(totpSecret, code) {
				slog.Warn("mfa: invalid TOTP code during enrollment", "request_id", middleware.GetRequestID(r.Context()), "ip", utils.GetClientIP(r))
				renderEnrollPage(w, r, challenge, usr, cfg, "Invalid verification code")
				return
			}
			if err := user.SaveTotpSecret(usr.ID, totpSecret); err != nil {
				slog.Error("mfa: failed to save TOTP secret", "request_id", middleware.GetRequestID(r.Context()), "error", err)
				utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to save TOTP secret")
				return
			}
		} else {
			// Verification flow: validate against stored secret
			if !ValidateTotpCode(usr.TotpSecret, code) {
				slog.Warn("mfa: invalid TOTP verification code", "request_id", middleware.GetRequestID(r.Context()), "ip", utils.GetClientIP(r))
				renderVerifyPage(w, r, challenge, cfg, "Invalid verification code")
				return
			}
		}
	case "email":
		hashedCode := utils.HashSHA256(code)
		if hashedCode != challenge.Code {
			slog.Warn("mfa: invalid email OTP code", "request_id", middleware.GetRequestID(r.Context()), "ip", utils.GetClientIP(r))
			renderVerifyPage(w, r, challenge, cfg, "Invalid verification code")
			return
		}
	default:
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Unknown MFA method")
		return
	}

	_ = MarkChallengeUsed(challenge.ID)

	// Save trusted device if requested
	if cfg.TrustDeviceEnabled && r.FormValue("trust_device") == "on" {
		deviceID, genErr := authcode.GenerateSecureCode()
		if genErr == nil {
			ua := r.UserAgent()
			if len(ua) > 200 {
				ua = ua[:200]
			}
			dev := trusteddevice.TrustedDevice{
				ID:         deviceID,
				UserID:     usr.ID,
				DeviceName: ua,
				ExpiresAt:  time.Now().Add(cfg.TrustDeviceExpiration),
			}
			if trusteddevice.CreateTrustedDevice(dev) == nil {
				trusteddevice.SetCookie(w, deviceID, cfg.TrustDeviceExpiration)
			}
		}
	}

	// Restore login state and complete the OAuth flow
	var loginState LoginState
	if err := json.Unmarshal([]byte(challenge.LoginState), &loginState); err != nil {
		slog.Error("mfa: failed to restore login state", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to restore login state")
		return
	}

	// Create IdP session if configured
	if cfg.AuthSsoSessionIdleTimeout > 0 {
		sessionID, err := authcode.GenerateSecureCode()
		if err == nil {
			session := idpsession.IdpSession{
				ID:        sessionID,
				UserID:    usr.ID,
				UserAgent: r.UserAgent(),
				IPAddress: utils.GetClientIP(r),
			}
			if idpsession.CreateIdpSession(session) == nil {
				idpsession.SetCookie(w, sessionID)
			}
		}
	}

	authorizationCode, err := authcode.GenerateSecureCode()
	if err != nil {
		slog.Error("mfa: failed to generate authorization code", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate authorization code")
		return
	}

	ac := authcode.AuthCode{
		Code:                authorizationCode,
		UserID:              usr.ID,
		ClientID:            loginState.ClientID,
		RedirectURI:         loginState.RedirectURI,
		Scope:               loginState.Scope,
		Nonce:               loginState.Nonce,
		CodeChallenge:       loginState.CodeChallenge,
		CodeChallengeMethod: loginState.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
		Used:                false,
	}

	if err := authcode.CreateAuthCode(ac); err != nil {
		slog.Error("mfa: failed to create authorization code", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create authorization code")
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", loginState.RedirectURI, ac.Code, loginState.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func renderVerifyPage(w http.ResponseWriter, r *http.Request, challenge *MfaChallenge, cfg *config.Config, errorMsg string) {
	tmpl, err := view.ParseTemplate("mfa")
	if err != nil {
		slog.Error("mfa: failed to parse verify template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"ChallengeID":        challenge.ID,
		"Method":             challenge.Method,
		"Error":              errorMsg,
		csrf.TemplateTag:     csrf.TemplateField(r),
		"ThemeTitle":         cfg.Theme.Title,
		"ThemeLogoUrl":       cfg.Theme.LogoUrl,
		"ThemeCssResolved":   template.CSS(cfg.ThemeCssResolved),
		"TrustDeviceEnabled": cfg.TrustDeviceEnabled,
		"TrustDeviceDays":    int(cfg.TrustDeviceExpiration.Hours() / 24),
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("mfa: failed to execute verify template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
	}
}

func renderEnrollPage(w http.ResponseWriter, r *http.Request, challenge *MfaChallenge, usr *user.User, cfg *config.Config, errorMsg string) {
	secret, otpauthURL, err := GenerateTotpSecret(usr.Username, cfg.Theme.Title)
	if err != nil {
		slog.Error("mfa: failed to generate TOTP secret", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate TOTP secret")
		return
	}

	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 200)
	if err != nil {
		slog.Error("mfa: failed to generate QR code", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate QR code")
		return
	}
	qrDataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)

	tmpl, err := view.ParseTemplate("mfa_enroll")
	if err != nil {
		slog.Error("mfa: failed to parse enroll template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"ChallengeID":      challenge.ID,
		"TotpSecret":       secret,
		"QRCodeDataURI":    template.URL(qrDataURI),
		"Error":            errorMsg,
		csrf.TemplateTag:   csrf.TemplateField(r),
		"ThemeTitle":       cfg.Theme.Title,
		"ThemeLogoUrl":     cfg.Theme.LogoUrl,
		"ThemeCssResolved": template.CSS(cfg.ThemeCssResolved),
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("mfa: failed to execute enroll template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
	}
}

func redirectToLoginWithError(w http.ResponseWriter, r *http.Request, challenge *MfaChallenge, errorMsg string) {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("error", errorMsg)

	if challenge != nil {
		var loginState LoginState
		if err := json.Unmarshal([]byte(challenge.LoginState), &loginState); err == nil {
			params.Set("client_id", loginState.ClientID)
			params.Set("redirect_uri", loginState.RedirectURI)
			params.Set("state", loginState.State)
			params.Set("scope", loginState.Scope)
			if loginState.Nonce != "" {
				params.Set("nonce", loginState.Nonce)
			}
			if loginState.CodeChallenge != "" {
				params.Set("code_challenge", loginState.CodeChallenge)
				params.Set("code_challenge_method", loginState.CodeChallengeMethod)
			}
		}
	}

	redirectURL := config.GetBootstrap().AppOAuthPath + "/authorize?" + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
