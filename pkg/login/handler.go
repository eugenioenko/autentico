package login

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
)

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
		Prompt:              r.FormValue("prompt"),
	}

	if config.Get().AuthMode == "passkey_only" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Password login is disabled; use passkey authentication")
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
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Authorization request parameters have been tampered with")
		return
	}

	// RFC 6749 §3.1.2: parse the absolute callback and preserve its query.
	redirectURL, err := url.Parse(request.RedirectURI)
	if err != nil || redirectURL.Scheme == "" || redirectURL.Host == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	// Validate client_id is registered and redirect_uri is allowed for this client
	// RFC 6749 §4.1.2.1: an invalid client identifier or redirection URI MUST NOT
	// cause a redirect to the client; respond directly instead (checks below).
	registeredClient, err := client.ClientByClientID(request.ClientID)
	if err != nil {
		slog.Warn("login: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
		return
	}
	if !registeredClient.IsActive {
		slog.Warn("login: inactive client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Client is inactive")
		return
	}
	if !client.IsValidRedirectURI(registeredClient, request.RedirectURI) {
		slog.Warn("login: redirect_uri not registered for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "redirect_uri", request.RedirectURI, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Redirect URI not allowed for this client")
		return
	}

	// Reject any scope that the client is not allowed to use
	// RFC 6749 §3.3: the AS MAY fully or partially ignore the requested scope based on its policy
	if !client.ValidateScopes(registeredClient, request.Scope) {
		slog.Warn("login: invalid scope for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "scope", request.Scope, "ip", utils.GetClientIP(r))
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
			slog.Warn("login: account locked", "request_id", reqid.Get(r.Context()), "username", request.Username, "ip", utils.GetClientIP(r))
		}
		detail := audit.Detail("username", request.Username, "reason", loginError)
		audit.Log(audit.EventLoginFailed, nil, audit.TargetUser, "", detail, utils.GetClientIP(r))
		redirectToLogin(w, r, request, loginError)
		return
	}

	// Email verification gate — non-admin users must verify before proceeding
	cfg := config.GetForClient(registeredClient.ToOverrides())
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

	// OIDC Core §3.1.2.3–4: every primary method shares MFA and consent.
	nextURL, err := mfa.FinishLogin(w, r, usr.ID, mfa.LoginState{
		RedirectURI:         request.RedirectURI,
		State:               request.State,
		ClientID:            request.ClientID,
		Scope:               request.Scope,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		Prompt:              request.Prompt,
	}, mfa.PrimaryPassword)
	if err != nil {
		slog.Error("login: failed to complete authentication", "request_id", reqid.Get(r.Context()), "error", err)
		redirectToLogin(w, r, request, "Something went wrong. Please try again.")
		return
	}
	// RFC 6749 §4.1.2: follow the validated next authentication step.
	http.Redirect(w, r, nextURL, http.StatusFound)
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
