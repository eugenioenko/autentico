package mfa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
	qrcode "github.com/skip2/go-qrcode"
)

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
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid or expired challenge")
		return
	}

	if challenge.Used || time.Now().After(challenge.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Challenge has expired")
		return
	}

	cfg := config.Get()

	if challenge.Method == "totp" {
		usr, err := user.UserByID(challenge.UserID)
		if err != nil {
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
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get user")
			return
		}
		otp, err := GenerateEmailOTP()
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate OTP")
			return
		}
		hashedOTP := utils.HashSHA256(otp)
		challenge.Code = hashedOTP
		_ = UpdateChallengeCode(challenge.ID, hashedOTP)
		if err := SendEmailOTP(usr.Email, otp); err != nil {
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
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid or expired challenge")
		return
	}

	if challenge.Used || time.Now().After(challenge.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Challenge has expired")
		return
	}

	cfg := config.Get()

	usr, err := user.UserByID(challenge.UserID)
	if err != nil {
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
				renderEnrollPage(w, r, challenge, usr, cfg, "Invalid verification code")
				return
			}
			if err := user.SaveTotpSecret(usr.ID, totpSecret); err != nil {
				utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to save TOTP secret")
				return
			}
		} else {
			// Verification flow: validate against stored secret
			if !ValidateTotpCode(usr.TotpSecret, code) {
				renderVerifyPage(w, r, challenge, cfg, "Invalid verification code")
				return
			}
		}
	case "email":
		hashedCode := utils.HashSHA256(code)
		if hashedCode != challenge.Code {
			renderVerifyPage(w, r, challenge, cfg, "Invalid verification code")
			return
		}
	default:
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Unknown MFA method")
		return
	}

	_ = MarkChallengeUsed(challenge.ID)

	// Restore login state and complete the OAuth flow
	var loginState LoginState
	if err := json.Unmarshal([]byte(challenge.LoginState), &loginState); err != nil {
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate authorization code")
		return
	}

	ac := authcode.AuthCode{
		Code:                authorizationCode,
		UserID:              usr.ID,
		ClientID:            loginState.ClientID,
		RedirectURI:         loginState.Redirect,
		Scope:               loginState.Scope,
		Nonce:               loginState.Nonce,
		CodeChallenge:       loginState.CodeChallenge,
		CodeChallengeMethod: loginState.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
		Used:                false,
	}

	if err := authcode.CreateAuthCode(ac); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create authorization code")
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", loginState.Redirect, ac.Code, loginState.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func renderVerifyPage(w http.ResponseWriter, r *http.Request, challenge *MfaChallenge, cfg *config.Config, errorMsg string) {
	tmpl, err := template.New("mfa").Parse(view.MfaTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"ChallengeID":    challenge.ID,
		"Method":         challenge.Method,
		"Error":          errorMsg,
		csrf.TemplateTag: csrf.TemplateField(r),
		"ThemeTitle":     cfg.Theme.Title,
		"ThemeLogoUrl":   cfg.Theme.LogoUrl,
		"ThemeCssResolved": template.CSS(cfg.ThemeCssResolved),
	}

	_ = tmpl.Execute(w, data)
}

func renderEnrollPage(w http.ResponseWriter, r *http.Request, challenge *MfaChallenge, usr *user.User, cfg *config.Config, errorMsg string) {
	secret, otpauthURL, err := GenerateTotpSecret(usr.Username, cfg.Theme.Title)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate TOTP secret")
		return
	}

	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 200)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate QR code")
		return
	}
	qrDataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)

	tmpl, err := template.New("mfa_enroll").Parse(view.MfaEnrollTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"ChallengeID":    challenge.ID,
		"TotpSecret":     secret,
		"QRCodeDataURI":  template.URL(qrDataURI),
		"Error":          errorMsg,
		csrf.TemplateTag: csrf.TemplateField(r),
		"ThemeTitle":     cfg.Theme.Title,
		"ThemeLogoUrl":   cfg.Theme.LogoUrl,
		"ThemeCssResolved": template.CSS(cfg.ThemeCssResolved),
	}

	_ = tmpl.Execute(w, data)
}
