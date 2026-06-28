package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/consent"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
)

const mfaChallengeExpiration = 10 * time.Minute

// HandleLoginUser handles user login requests.
// CSRF-protected form — not included in public API docs.
//
// Method: POST
// Route: /oauth2/login
// Accept: application/x-www-form-urlencoded
// Produce: json
// Param username formData string true "Username"
// Param password formData string true "Password"
// Param redirect formData string true "Redirect URI"
// Param state formData string true "State"
// Success 302 "Redirect to the provided URI with code and state"
// Failure 400 model.ApiError
// Failure 500 model.ApiError
func HandleLoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		view.RenderError(w, r, http.StatusMethodNotAllowed, "This page can only be accessed through the login flow.")
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "请求负载必须是 application/x-www-form-urlencoded 格式")
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
		Prompt:              r.FormValue("prompt"),
	}

	if config.Get().AuthMode == "passkey_only" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "密码登录已禁用；请使用通行密钥认证")
		return
	}

	// Verify HMAC signature to prevent authorize parameter tampering (#184, #186)
	authorizeSig := r.FormValue("authorize_sig")
	if !authzsig.Verify(authzsig.AuthorizeParams{
		ClientID:            request.ClientID,
		RedirectURI:         request.RedirectURI,
		Scope:               request.Scope,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		State:               request.State,
	}, authorizeSig) {
		slog.Warn("login: authorize parameter signature mismatch", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "授权请求参数已被篡改")
		return
	}

	// Validate redirect_uri format first
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "无效的重定向URI")
		return
	}

	// Validate client_id is registered and redirect_uri is allowed for this client
	registeredClient, err := client.ClientByClientID(request.ClientID)
	if err != nil {
		slog.Warn("login: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "未知的客户端ID")
		return
	}
	if !registeredClient.IsActive {
		slog.Warn("login: inactive client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "客户端未激活")
		return
	}
	if !client.IsValidRedirectURI(registeredClient, request.RedirectURI) {
		slog.Warn("login: redirect_uri not registered for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "redirect_uri", request.RedirectURI, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "重定向URI不在此客户端的允许列表中")
		return
	}

	// Reject any scope that the client is not allowed to use
	if !client.ValidateScopes(registeredClient, request.Scope) {
		slog.Warn("login: invalid scope for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "scope", request.Scope, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "此客户端不允许使用所请求的一个或多个权限范围")
		return
	}

	err = ValidateLoginRequest(request)
	if err != nil {
		redirectToLogin(w, r, request, fmt.Sprintf("用户凭证错误：%v", err))
		return
	}

	usr, err := user.AuthenticateUser(request.Username, request.Password)
	if err != nil {
		loginError := "用户名或密码无效"
		if errors.Is(err, user.ErrAccountLocked) {
			loginError = "账户因登录尝试次数过多已被暂时锁定"
			slog.Warn("login: account locked", "request_id", reqid.Get(r.Context()), "username", request.Username, "ip", utils.GetClientIP(r))
		}
		detail := audit.Detail("username", request.Username, "reason", loginError)
		audit.Log(audit.EventLoginFailed, nil, audit.TargetUser, "", detail, utils.GetClientIP(r))
		redirectToLogin(w, r, request, loginError)
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
			AuthorizeSig:        authorizeSig,
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
				slog.Error("login: email MFA required but SMTP is not configured", "request_id", reqid.Get(r.Context()))
				redirectToLogin(w, r, request, "邮箱验证不可用，请联系支持。")
				return
			}
		}
		// For TOTP method with unenrolled user, force enrollment
		// For email method, always proceed (no per-user setup needed)

		loginState := mfa.LoginState{
			RedirectURI:         request.RedirectURI,
			State:               request.State,
			ClientID:            request.ClientID,
			Scope:               request.Scope,
			Nonce:               request.Nonce,
			CodeChallenge:       request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
			Prompt:              request.Prompt,
		}
		stateJSON, err := json.Marshal(loginState)
		if err != nil {
			slog.Error("login: failed to serialize login state", "request_id", reqid.Get(r.Context()), "error", err)
			redirectToLogin(w, r, request, "出现错误，请重试。")
			return
		}

		challengeID, err := authcode.GenerateSecureCode()
		if err != nil {
			slog.Error("login: failed to generate challenge ID", "request_id", reqid.Get(r.Context()), "error", err)
			redirectToLogin(w, r, request, "出现错误，请重试。")
			return
		}

		challenge := mfa.MfaChallenge{
			ID:         challengeID,
			UserID:     usr.ID,
			Method:     method,
			LoginState: string(stateJSON),
			ExpiresAt:  time.Now().Add(mfaChallengeExpiration),
		}

		if err := mfa.CreateMfaChallenge(challenge); err != nil {
			slog.Error("login: failed to create MFA challenge", "request_id", reqid.Get(r.Context()), "error", err)
			redirectToLogin(w, r, request, "出现错误，请重试。")
			return
		}

		mfaURL := config.GetBootstrap().AppOAuthPath + "/mfa?challenge_id=" + challengeID
		http.Redirect(w, r, mfaURL, http.StatusFound)
		return
	}

	idpSessionID := idpsession.FinalizeLogin(w, r, usr.ID)

	// OIDC Core §3.1.2.4: check if consent is needed before issuing auth code
	if consent.NeedsConsent(registeredClient.ConsentRequired, usr.ID, request.ClientID, request.Scope, request.Prompt) {
		consent.RedirectToConsent(w, r, consent.ConsentParams{
			RedirectURI:         request.RedirectURI,
			State:               request.State,
			ClientID:            request.ClientID,
			Scope:               request.Scope,
			Nonce:               request.Nonce,
			CodeChallenge:       request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
			Prompt:              request.Prompt,
		})
		return
	}

	authCode, err := authcode.GenerateSecureCode()
	if err != nil {
		slog.Error("login: failed to generate auth code", "request_id", reqid.Get(r.Context()), "error", err)
		redirectToLogin(w, r, request, "Something went wrong. Please try again.")
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
		IdpSessionID:        idpSessionID,
	}

	err = authcode.CreateAuthCode(code)
	if err != nil {
		slog.Error("login: failed to create auth code", "request_id", reqid.Get(r.Context()), "error", err)
		redirectToLogin(w, r, request, "Something went wrong. Please try again.")
		return
	}

	audit.Log(audit.EventLoginSuccess, usr, audit.TargetUser, usr.ID, audit.Detail("method", "password"), utils.GetClientIP(r))

	// RFC 6749 §4.1.2: authorization response MUST include code; state MUST be echoed unchanged if present
	params := url.Values{}
	params.Set("code", code.Code)
	if request.State != "" {
		params.Set("state", request.State)
	}
	http.Redirect(w, r, request.RedirectURI+"?"+params.Encode(), http.StatusFound)
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

