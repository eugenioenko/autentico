package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/authrequest"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

// HandleLoginPage renders the login form. It reads the auth_request_id from the
// query string and looks up the stored authorize parameters from the database.
func HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_request_id")
	if authReqID == "" {
		renderLoginError(w, "Missing authorization request. Please return to the application and try again.")
		return
	}

	authReq, err := authrequest.GetByID(authReqID)
	if err != nil {
		slog.Warn("login_page: invalid or expired auth request", "auth_request_id", authReqID, "error", err)
		renderLoginError(w, "Authorization request expired. Please return to the application and try again.")
		return
	}

	errorMsg := r.URL.Query().Get("error")
	renderLogin(w, r, authReq, errorMsg)
}

// renderLogin renders the login form using stored authorize request parameters.
func renderLogin(w http.ResponseWriter, r *http.Request, authReq *authrequest.AuthorizeRequest, errorMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("login")
	if err != nil {
		slog.Error("login: failed to parse login template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	federatedProviders, _ := federation.ListEnabledProviderViews()

	data := map[string]any{
		"AuthRequestID":       authReq.ID,
		"ClientID":            authReq.ClientID,
		"Error":               errorMsg,
		"AuthMode":            cfg.AuthMode,
		"AllowSelfSignup":     cfg.AuthAllowSelfSignup,
		"ProfileFieldEmail":   cfg.ProfileFieldEmail,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeCssResolved":    template.CSS(cfg.ThemeCssResolved),
		"SmtpConfigured":      cfg.SmtpHost != "",
		"FederatedProviders":  federatedProviders,
	}

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("login: failed to execute login template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// renderLoginError renders a branded error page for authorization request failures.
func renderLoginError(w http.ResponseWriter, errorMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("error")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Error":            errorMsg,
		"ThemeTitle":       cfg.Theme.Title,
		"ThemeLogoUrl":     cfg.Theme.LogoUrl,
		"ThemeCssResolved": template.CSS(cfg.ThemeCssResolved),
	}
	w.WriteHeader(http.StatusBadRequest)
	_ = tmpl.ExecuteTemplate(w, "layout", data)
}

// HandleLoginUser godoc
// @Summary Log in a user
// @Description Authenticates a user and generates an authorization code
// @Tags auth
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param username formData string true "Username"
// @Param password formData string true "Password"
// @Param redirect formData string true "Redirect URI"
// @Param state formData string true "State"
// @Success 302 {string} string "Redirect to the provided URI with code and state"
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/login [post]
func HandleLoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Only POST method is allowed")
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	// Look up the stored authorize request — all OAuth parameters come from the
	// server-side record, not from the POST body. This prevents parameter tampering
	// (PKCE downgrade, scope escalation, nonce injection — issues #184, #186).
	authReqID := r.FormValue("auth_request_id")
	if authReqID == "" {
		renderLoginError(w, "Missing authorization request. Please return to the application and try again.")
		return
	}

	authReq, err := authrequest.GetByID(authReqID)
	if err != nil {
		slog.Warn("login: invalid or expired auth request", "request_id", middleware.GetRequestID(r.Context()), "auth_request_id", authReqID, "error", err)
		renderLoginError(w, "Authorization request expired. Please return to the application and try again.")
		return
	}

	// Only username and password come from the POST body
	request := LoginRequest{
		Username:            r.FormValue("username"),
		Password:            r.FormValue("password"),
		RedirectURI:         authReq.RedirectURI,
		State:               authReq.State,
		ClientID:            authReq.ClientID,
		Scope:               authReq.Scope,
		Nonce:               authReq.Nonce,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
	}

	if config.Get().AuthMode == "passkey_only" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Password login is disabled; use passkey authentication")
		return
	}

	err = ValidateLoginRequest(request)
	if err != nil {
		redirectToLogin(w, r, authReqID, fmt.Sprintf("user credentials error. %v", err))
		return
	}

	usr, err := user.AuthenticateUser(request.Username, request.Password)
	if err != nil {
		loginError := "Invalid username or password"
		if errors.Is(err, user.ErrAccountLocked) {
			loginError = "Account is temporarily locked due to too many failed login attempts"
			slog.Warn("login: account locked", "request_id", middleware.GetRequestID(r.Context()), "username", request.Username, "ip", utils.GetClientIP(r))
		}
		detail := audit.Detail("username", request.Username, "reason", loginError)
		audit.Log(audit.EventLoginFailed, nil, audit.TargetUser, "", detail, utils.GetClientIP(r))
		redirectToLogin(w, r, authReqID, loginError)
		return
	}

	// Email verification gate — non-admin users must verify before proceeding
	cfg := config.Get()
	if cfg.RequireEmailVerification && !usr.IsEmailVerified && usr.Role != "admin" {
		emailverification.RenderVerifyEmail(w, r, "blocked", usr.Username, emailverification.OAuthParams{
			RedirectURI:         request.RedirectURI,
			State:               request.State,
			ClientID:            request.ClientID,
			Scope:               request.Scope,
			Nonce:               request.Nonce,
			CodeChallenge:       request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
		}, "")
		return
	}

	// MFA check: required globally, or user has voluntarily enrolled in TOTP
	skipMfa := cfg.TrustDeviceEnabled && trusteddevice.IsDeviceTrusted(usr.ID, r)
	if (cfg.RequireMfa || usr.TotpVerified) && !skipMfa {
		method := cfg.MfaMethod
		if !cfg.RequireMfa && usr.TotpVerified {
			// User enrolled voluntarily — always use their TOTP regardless of global method
			method = "totp"
		} else if method == "both" {
			// If method is "both", prefer TOTP if user is enrolled, otherwise email
			if usr.TotpVerified {
				method = "totp"
			} else {
				method = "email"
			}
		}
		// Block email OTP if SMTP is not configured
		if method == "email" && cfg.SmtpHost == "" {
			if usr.TotpVerified {
				method = "totp"
			} else {
				slog.Error("login: email MFA required but SMTP is not configured", "request_id", middleware.GetRequestID(r.Context()))
				redirectToLogin(w, r, authReqID,"Email verification is not available. Please contact support.")
				return
			}
		}
		// For TOTP method with unenrolled user, force enrollment
		// For email method, always proceed (no per-user setup needed)

		loginState := mfa.LoginState{
			RedirectURI:            request.RedirectURI,
			State:               request.State,
			ClientID:            request.ClientID,
			Scope:               request.Scope,
			Nonce:               request.Nonce,
			CodeChallenge:       request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
		}
		stateJSON, err := json.Marshal(loginState)
		if err != nil {
			slog.Error("login: failed to serialize login state", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			redirectToLogin(w, r, authReqID,"Something went wrong. Please try again.")
			return
		}

		challengeID, err := authcode.GenerateSecureCode()
		if err != nil {
			slog.Error("login: failed to generate challenge ID", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			redirectToLogin(w, r, authReqID,"Something went wrong. Please try again.")
			return
		}

		challenge := mfa.MfaChallenge{
			ID:         challengeID,
			UserID:     usr.ID,
			Method:     method,
			LoginState: string(stateJSON),
			ExpiresAt:  time.Now().Add(5 * time.Minute),
		}

		if err := mfa.CreateMfaChallenge(challenge); err != nil {
			slog.Error("login: failed to create MFA challenge", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			redirectToLogin(w, r, authReqID,"Something went wrong. Please try again.")
			return
		}

		mfaURL := config.GetBootstrap().AppOAuthPath + "/mfa?challenge_id=" + challengeID
		http.Redirect(w, r, mfaURL, http.StatusFound)
		return
	}

	// Create IdP session if authSsoSessionIdleTimeout is enabled
	if config.Get().AuthSsoSessionIdleTimeout > 0 {
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

	authCode, err := authcode.GenerateSecureCode()
	if err != nil {
		slog.Error("login: failed to generate auth code", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		redirectToLogin(w, r, authReqID,"Something went wrong. Please try again.")
		return
	}

	code := authcode.AuthCode{
		Code:                authCode,
		UserID:              usr.ID,
		ClientID:            request.ClientID,
		RedirectURI:         request.RedirectURI,
		Scope:               request.Scope,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(config.Get().AuthAuthorizationCodeExpiration),
		Used:                false,
	}

	err = authcode.CreateAuthCode(code)
	if err != nil {
		slog.Error("login: failed to create auth code", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		redirectToLogin(w, r, authReqID, "Something went wrong. Please try again.")
		return
	}

	// Consume the authorize request to prevent reuse (e.g. browser back button)
	_ = authrequest.Delete(authReqID)

	audit.Log(audit.EventLoginSuccess, usr, audit.TargetUser, usr.ID, audit.Detail("method", "password"), utils.GetClientIP(r))

	// RFC 6749 §4.1.2: authorization response MUST include code; state MUST be echoed unchanged if present
	params := url.Values{}
	params.Set("code", code.Code)
	if request.State != "" {
		params.Set("state", request.State)
	}
	http.Redirect(w, r, request.RedirectURI+"?"+params.Encode(), http.StatusFound)
}

// redirectToLogin redirects back to the login page with an error message,
// preserving the auth request ID so the form is re-rendered with stored params.
func redirectToLogin(w http.ResponseWriter, r *http.Request, authReqID string, loginError string) {
	loginURL := config.GetBootstrap().AppOAuthPath + "/login?auth_request_id=" + authReqID + "&error=" + url.QueryEscape(loginError)
	http.Redirect(w, r, loginURL, http.StatusFound)
}
