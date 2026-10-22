package authorize

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/consent"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/signup"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"

	"github.com/gorilla/csrf"
)

// HandleAuthorize godoc
// @Summary Authorize a client
// @Description Handles the authorization request and displays the login page
// @Tags oauth2
// @Accept json
// @Produce html
// @Param response_type query string true "Response type"
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param scope query string false "Scope"
// @Param state query string true "State"
// @Success 200 {string} string "HTML login page"
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/authorize [get]
func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Support both GET (query string) and POST (form body) per OIDC Core §3.1.2.1
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			slog.Warn("authorize: failed to parse POST form", "error", err)
		}
	}
	get := func(key string) string {
		if r.Method == http.MethodPost {
			return r.FormValue(key)
		}
		return r.URL.Query().Get(key)
	}

	request := AuthorizeRequest{
		ResponseType:        get("response_type"),
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		Scope:               get("scope"),
		State:               get("state"),
		Nonce:               get("nonce"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
		Prompt:              get("prompt"),
		MaxAge:              get("max_age"),
	}

	// Validate redirect_uri format first — if invalid we cannot redirect back safely
	// RFC 6749 §3.1.2.4 / §4.1.2.1: on a missing or invalid redirection URI the AS
	// SHOULD inform the resource owner and MUST NOT redirect the user-agent.
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		view.RenderError(w, r, http.StatusBadRequest, "Invalid redirect_uri")
		return
	}

	// Validate client_id — if unknown we cannot redirect back safely
	// RFC 6749 §4.1.2.1: if the client identifier is missing or invalid, the AS
	// SHOULD inform the resource owner and MUST NOT redirect the user-agent.
	registeredClient, err := client.ClientByClientID(request.ClientID)
	if err != nil {
		slog.Warn("authorize: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		view.RenderError(w, r, http.StatusBadRequest, "Unknown client_id")
		return
	}

	// RFC 6749 §4.1.2.1: an inactive client is an invalid client identifier; do not redirect.
	if !registeredClient.IsActive {
		slog.Warn("authorize: inactive client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		view.RenderError(w, r, http.StatusBadRequest, "Client is inactive")
		return
	}

	// RFC 6749 §4.1.3: redirect_uri MUST match a URI registered for the client;
	// if invalid, do not redirect — render an error page instead to avoid open redirector.
	if !client.IsValidRedirectURI(registeredClient, request.RedirectURI) {
		slog.Warn("authorize: invalid redirect_uri for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "redirect_uri", request.RedirectURI)
		view.RenderError(w, r, http.StatusBadRequest, "Redirect URI not allowed for this client")
		return
	}

	// From here redirect_uri and client are trusted — redirect back with error for all remaining failures

	// Reject request objects — not supported (OIDC Core §6.1 / OIDCC-3.1.2.6)
	if get("request") != "" {
		redirectWithError(w, r, request.RedirectURI, request.State, "request_not_supported", "request objects are not supported")
		return
	}

	// RFC 6749 §4.1.2.1: invalid_request: missing required parameter or invalid parameter value
	if err := ValidateAuthorizeRequest(request); err != nil {
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_request", err.Error())
		return
	}

	// RFC 9700 §2.1.1: public clients MUST use PKCE — reject if code_challenge is missing
	if registeredClient.ClientType == "public" && request.CodeChallenge == "" {
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_request", "code_challenge is required for public clients")
		return
	}

	// RFC 7636 §7.2: "plain" SHOULD NOT be used; §4.2: S256 is MTI on the server
	if request.CodeChallengeMethod == "plain" && config.Get().AuthPKCEEnforceSHA256 {
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_request", "code_challenge_method 'plain' is not allowed; use S256")
		return
	}

	// RFC 6749 §3.1.1 / §4.1.2.1: unsupported_response_type for a response type the client may not use
	// RFC 6749 §3.1.1 / §4.1.2.1: registration cannot enable an unimplemented flow.
	if request.ResponseType != "code" || !client.IsResponseTypeAllowed(registeredClient, request.ResponseType) {
		slog.Warn("authorize: invalid response_type for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "response_type", request.ResponseType)
		redirectWithError(w, r, request.RedirectURI, request.State, "unsupported_response_type", "response_type not allowed for this client")
		return
	}

	// RFC 6749 §3.3 / §4.1.2.1: invalid_scope: requested scope exceeds what the client may request
	if !client.ValidateScopes(registeredClient, request.Scope) {
		slog.Warn("authorize: invalid scope for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "scope", request.Scope)
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_scope", "one or more requested scopes are not allowed for this client")
		return
	}

	// OIDC Core §3.1.2.1: prompt=login requires fresh authentication — skip SSO auto-login
	// OIDC Core §3.1.2.1: prompt=consent requires user consent — skip SSO auto-login
	cfg := config.GetForClient(registeredClient.ToOverrides())
	autoLoginResult := tryAutoLogin(r, &cfg, request, registeredClient)
	if autoLoginResult.redirectURL != "" {
		http.Redirect(w, r, autoLoginResult.redirectURL, http.StatusFound)
		return
	}
	// OIDC Core §3.1.2.1: silent authorization cannot display consent.
	if client.HasPrompt(request.Prompt, "none") {
		if autoLoginResult.needsConsent {
			redirectWithError(w, r, request.RedirectURI, request.State, "consent_required", "")
		} else {
			redirectWithError(w, r, request.RedirectURI, request.State, "login_required", "")
		}
		return
	}
	if autoLoginResult.needsConsent {
		consent.RedirectToConsent(w, r, consent.ConsentParams{
			RedirectURI: request.RedirectURI, State: request.State, ClientID: request.ClientID,
			Scope: request.Scope, Nonce: request.Nonce, CodeChallenge: request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
			Prompt:              request.Prompt,
			MaxAge:              request.MaxAge,
		})
		return
	}

	// OIDC Core §3.1.2.1: prompt=create signals the client wants the registration form
	if client.HasPrompt(request.Prompt, "create") {
		if !cfg.AuthAllowSelfSignup {
			renderLogin(w, r, request, "Self-registration is not enabled")
			return
		}
		signup.RenderSignup(w, r, signup.SignupParams{
			State:               request.State,
			RedirectURI:         request.RedirectURI,
			ClientID:            request.ClientID,
			Scope:               request.Scope,
			Nonce:               request.Nonce,
			CodeChallenge:       request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
			AuthorizeSig:        AuthorizeSignature(request),
			Prompt:              request.Prompt,
			MaxAge:              request.MaxAge,
		}, get("error"))
		return
	}

	// If the authorize request arrived as POST, redirect to GET so that the CSRF
	// middleware runs and sets the CSRF cookie before rendering the login form.
	// OIDC Core §3.1.2.1: the AS MUST support both GET and POST; POST parameters
	// are carried over unchanged to the equivalent GET request.
	if r.Method == http.MethodPost {
		q := url.Values{}
		q.Set("response_type", request.ResponseType)
		q.Set("client_id", request.ClientID)
		q.Set("redirect_uri", request.RedirectURI)
		q.Set("scope", request.Scope)
		q.Set("state", request.State)
		q.Set("nonce", request.Nonce)
		q.Set("code_challenge", request.CodeChallenge)
		q.Set("code_challenge_method", request.CodeChallengeMethod)
		q.Set("prompt", request.Prompt)
		q.Set("max_age", request.MaxAge)
		http.Redirect(w, r, config.GetBootstrap().AppOAuthPath+"/authorize?"+q.Encode(), http.StatusFound)
		return
	}

	renderLogin(w, r, request, get("error"))
}

// renderLogin renders the login form, or an error-only page when errorMsg is a fatal
// configuration problem (e.g. invalid redirect URI) where submitting the form makes no sense.
func renderLogin(w http.ResponseWriter, r *http.Request, request AuthorizeRequest, errorMsg string) {
	cfg := *config.Get()
	// RFC 6749 §2: registration policy also determines the visible signup entry.
	if registeredClient, err := client.ClientByClientID(request.ClientID); err == nil && registeredClient.IsActive {
		cfg = config.GetForClient(registeredClient.ToOverrides())
	} else {
		cfg.AuthAllowSelfSignup = false
	}
	tmpl, err := view.ParseTemplate("login")
	if err != nil {
		slog.Error("authorize: failed to parse login template", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	federatedProviders, _ := federation.ListEnabledProviderViews()

	signupPrompt := "create"
	if client.HasPrompt(request.Prompt, "consent") {
		signupPrompt += " consent"
	}
	signupQuery := url.Values{
		"response_type": {"code"}, "client_id": {request.ClientID}, "redirect_uri": {request.RedirectURI},
		"scope": {request.Scope}, "state": {request.State}, "nonce": {request.Nonce},
		"code_challenge": {request.CodeChallenge}, "code_challenge_method": {request.CodeChallengeMethod},
		"prompt": {signupPrompt}, "max_age": {request.MaxAge},
	}
	data := map[string]any{
		"SignupURL":           config.GetBootstrap().AppOAuthPath + "/authorize?" + signupQuery.Encode(),
		"State":               request.State,
		"RedirectURI":         request.RedirectURI,
		"ClientID":            request.ClientID,
		"Scope":               request.Scope,
		"Nonce":               request.Nonce,
		"CodeChallenge":       request.CodeChallenge,
		"CodeChallengeMethod": request.CodeChallengeMethod,
		"Prompt":              request.Prompt,
		"AuthorizeSig":        AuthorizeSignature(request),
		"Error":               errorMsg,
		"AuthMode":            cfg.AuthMode,
		"PasskeyLoginMode":    cfg.PasskeyLoginMode,
		"HideUsernameField":   cfg.AuthMode == "passkey_only" && cfg.PasskeyLoginMode == "passkey_only",
		"HidePasswordField":   cfg.AuthMode == "passkey_only",
		"ShowLoginButton":     cfg.AuthMode != "passkey_only",
		"AllowSelfSignup":     cfg.AuthAllowSelfSignup,
		"ProfileFieldEmail":   cfg.ProfileFieldEmail,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeTagline":        cfg.Theme.Tagline,
		"SmtpConfigured":      cfg.SmtpHost != "",
		"MagicLinkEnabled":    cfg.MagicLinkEnabled && cfg.SmtpHost != "",
		"FederatedProviders":  federatedProviders,
		"MaxAge":              request.MaxAge,
	}
	view.InjectNonce(r, data)

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("authorize: failed to execute login template", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// redirectWithError redirects back to the redirect_uri with OAuth2 error params.
// Per RFC 6749 §4.1.2.1 and Appendix B, all query values are percent-encoded.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	// RFC 6749 §3.1.2: preserve the callback query for error responses too.
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}
	q := redirectURL.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

type autoLoginResult struct {
	redirectURL  string
	needsConsent bool
	hasSession   bool
	userID       string
}

// tryAutoLogin checks for a valid IdP session and returns a redirect URL with
// an authorization code if SSO auto-login succeeds. Returns empty redirectURL if
// auto-login should not or cannot proceed.
func tryAutoLogin(r *http.Request, cfg *config.Config, request AuthorizeRequest, registeredClient *client.Client) autoLoginResult {
	promptValues := strings.Fields(request.Prompt)
	hasLogin := false
	hasConsent := false
	for _, v := range promptValues {
		if v == "login" {
			hasLogin = true
		}
		if v == "consent" {
			hasConsent = true
		}
	}

	// OIDC Core §3.1.2.1: prompt=login: the AS SHOULD prompt the End-User for reauthentication.
	if !cfg.AuthSsoEnabled || hasLogin || client.HasPrompt(request.Prompt, "create") {
		return autoLoginResult{}
	}

	sessionID := idpsession.ReadCookie(r)
	if sessionID == "" {
		return autoLoginResult{}
	}

	session, err := idpsession.IdpSessionByID(sessionID)
	if err != nil {
		return autoLoginResult{}
	}
	// OIDC Core §3.1.2.3: SSO must not bypass local MFA enabled after the
	// session was created, or infer completion from the user's enrollment.
	usr, err := user.UserByID(session.UserID)
	if err != nil || !idpsession.SatisfiesMfa(session.MfaMethod, usr, cfg) {
		// OIDC Core §3.1.2.1: this session cannot authenticate the request;
		// prompt=none needs login_required even when consent is also missing.
		return autoLoginResult{}
	}

	// OIDC Core §3.1.2.1: max_age: if the elapsed time since the last active
	// authentication exceeds max_age, the OP MUST actively re-authenticate the End-User.
	now := time.Now()
	maxAgeSecs, err := client.ParseMaxAge(request.MaxAge)
	// OIDC Core §3.1.2.1 / §3.1.2.3: expired sessions do not authenticate
	// the request, even if the client would otherwise also need consent.
	if err != nil || !idpsession.IsFresh(session, cfg, now) || !idpsession.WithinMaxAge(session, maxAgeSecs, now) {
		return autoLoginResult{}
	}

	_ = idpsession.UpdateLastActivity(session.ID)

	// OIDC Core §3.1.2.4: check consent before issuing auth code
	if hasConsent || consent.NeedsConsent(registeredClient.ConsentRequired, session.UserID, request.ClientID, request.Scope, request.Prompt) {
		return autoLoginResult{needsConsent: true, hasSession: true, userID: session.UserID}
	}

	// RFC 6749 §3.1.2: parse before issuing a code and retain existing queries.
	redirectURL, err := url.Parse(request.RedirectURI)
	if err != nil {
		return autoLoginResult{hasSession: true, userID: session.UserID}
	}

	code, err := authcode.GenerateSecureCode()
	if err != nil {
		return autoLoginResult{hasSession: true, userID: session.UserID}
	}

	ac := authcode.AuthCode{
		Code:                code,
		UserID:              session.UserID,
		ClientID:            request.ClientID,
		RedirectURI:         request.RedirectURI,
		Scope:               request.Scope,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
		Used:                false,
		CreatedAt:           session.CreatedAt,
		IdpSessionID:        session.ID,
	}
	if err := authcode.CreateAuthCode(ac); err != nil {
		return autoLoginResult{hasSession: true, userID: session.UserID}
	}

	// RFC 6749 §4.1.2: authorization response MUST include code; state MUST be echoed unchanged if present
	redirectParams := redirectURL.Query()
	redirectParams.Set("code", ac.Code)
	if request.State != "" {
		redirectParams.Set("state", request.State)
	}
	redirectURL.RawQuery = redirectParams.Encode()
	return autoLoginResult{redirectURL: redirectURL.String(), hasSession: true, userID: session.UserID}
}
