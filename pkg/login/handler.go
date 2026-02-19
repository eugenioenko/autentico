package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
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
		Redirect:            r.FormValue("redirect"),
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

	err = ValidateLoginRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("user credentials error. %v", err))
		return
	}

	// Validate redirect_uri
	if !utils.IsValidRedirectURI(request.Redirect) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	usr, err := user.AuthenticateUser(request.Username, request.Password)
	if err != nil {
		loginError := "Invalid username or password"
		if errors.Is(err, user.ErrAccountLocked) {
			loginError = "Account is temporarily locked due to too many failed login attempts"
		}
		redirectToLogin(w, r, request, loginError)
		return
	}

	// MFA check: if enabled globally, redirect to MFA verification
	cfg := config.Get()
	skipMfa := cfg.TrustDeviceEnabled && trusteddevice.IsDeviceTrusted(usr.ID, r)
	if cfg.MfaEnabled && !skipMfa {
		method := cfg.MfaMethod
		// If method is "both", prefer TOTP if user is enrolled, otherwise email
		if method == "both" {
			if usr.TotpVerified {
				method = "totp"
			} else {
				method = "email"
			}
		}
		// For TOTP method with unenrolled user, force enrollment
		// For email method, always proceed (no per-user setup needed)

		loginState := mfa.LoginState{
			Redirect:            request.Redirect,
			State:               request.State,
			ClientID:            request.ClientID,
			Scope:               request.Scope,
			Nonce:               request.Nonce,
			CodeChallenge:       request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
		}
		stateJSON, err := json.Marshal(loginState)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to serialize login state")
			return
		}

		challengeID, err := authcode.GenerateSecureCode()
		if err != nil {
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
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create MFA challenge")
			return
		}

		mfaURL := cfg.AppOAuthPath + "/mfa?challenge_id=" + challengeID
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code generation. %v", err))
		return
	}

	code := authcode.AuthCode{
		Code:                authCode,
		UserID:              usr.ID,
		ClientID:            request.ClientID,
		RedirectURI:         request.Redirect,
		Scope:               request.Scope,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(config.Get().AuthAuthorizationCodeExpiration),
		Used:                false,
	}

	err = authcode.CreateAuthCode(code)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code insert. %v", err))
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", request.Redirect, code.Code, request.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// redirectToLogin redirects back to the authorize endpoint with an error message,
// preserving all original OAuth parameters so the login form is re-rendered.
func redirectToLogin(w http.ResponseWriter, r *http.Request, req LoginRequest, loginError string) {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", req.ClientID)
	params.Set("redirect_uri", req.Redirect)
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
	redirectURL := config.Get().AppOAuthPath + "/authorize?" + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
