package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

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

	request := LoginRequest{
		Username:            r.FormValue("username"),
		Password:            r.FormValue("password"),
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		ClientID:            r.FormValue("client_id"),
		Scope:               r.FormValue("scope"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	if config.Get().AuthMode == "passkey_only" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Password login is disabled; use passkey authentication")
		return
	}

	// Validate redirect_uri format first
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	// Validate client_id is registered and redirect_uri is allowed for this client
	registeredClient, err := client.ClientByClientID(request.ClientID)
	if err != nil {
		slog.Warn("login: unknown client_id", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
		return
	}
	if !registeredClient.IsActive {
		slog.Warn("login: inactive client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Client is inactive")
		return
	}
	if !client.IsValidRedirectURI(registeredClient, request.RedirectURI) {
		slog.Warn("login: redirect_uri not registered for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "redirect_uri", request.RedirectURI, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Redirect URI not allowed for this client")
		return
	}

	// Reject any scope that the client is not allowed to use
	if !client.ValidateScopes(registeredClient, request.Scope) {
		slog.Warn("login: invalid scope for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "scope", request.Scope, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "One or more requested scopes are not allowed for this client")
		return
	}

	err = ValidateLoginRequest(request)
	if err != nil {
		redirectToLogin(w, r, request, fmt.Sprintf("user credentials error. %v", err))
		return
	}

	usr, err := user.AuthenticateUser(request.Username, request.Password)
	if err != nil {
		loginError := "Invalid username or password"
		if errors.Is(err, user.ErrAccountLocked) {
			loginError = "Account is temporarily locked due to too many failed login attempts"
			slog.Warn("login: account locked", "request_id", middleware.GetRequestID(r.Context()), "username", request.Username, "ip", utils.GetClientIP(r))
		}
		redirectToLogin(w, r, request, loginError)
		return
	}

	// MFA check: required globally, or user has voluntarily enrolled in TOTP
	cfg := config.Get()
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
				utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Email MFA is not available: SMTP is not configured")
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
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to serialize login state")
			return
		}

		challengeID, err := authcode.GenerateSecureCode()
		if err != nil {
			slog.Error("login: failed to generate challenge ID", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate challenge ID")
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
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create MFA challenge")
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code generation. %v", err))
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code insert. %v", err))
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", request.RedirectURI, code.Code, request.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// redirectToLogin redirects back to the authorize endpoint with an error message,
// preserving all original OAuth parameters so the login form is re-rendered.
func redirectToLogin(w http.ResponseWriter, r *http.Request, req LoginRequest, loginError string) {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", req.ClientID)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("state", req.State)
	params.Set("scope", req.Scope)
	params.Set("error", loginError)
	if req.Nonce != "" {
		params.Set("nonce", req.Nonce)
	}
	if req.CodeChallenge != "" {
		params.Set("code_challenge", req.CodeChallenge)
		params.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	redirectURL := config.GetBootstrap().AppOAuthPath + "/authorize?" + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
