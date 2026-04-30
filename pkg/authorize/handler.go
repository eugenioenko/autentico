package authorize

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
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
		_ = r.ParseForm()
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
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		renderError(w, "Invalid redirect_uri")
		return
	}

	// Validate client_id — if unknown we cannot redirect back safely
	registeredClient, err := client.ClientByClientID(request.ClientID)
	if err != nil {
		slog.Warn("authorize: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		renderError(w, "Unknown client_id")
		return
	}

	if !registeredClient.IsActive {
		slog.Warn("authorize: inactive client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		renderError(w, "Client is inactive")
		return
	}

	// RFC 6749 §4.1.3: redirect_uri MUST match a URI registered for the client;
	// if invalid, do not redirect — render an error page instead to avoid open redirector.
	if !client.IsValidRedirectURI(registeredClient, request.RedirectURI) {
		slog.Warn("authorize: invalid redirect_uri for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "redirect_uri", request.RedirectURI)
		renderError(w, "Redirect URI not allowed for this client")
		return
	}

	// From here redirect_uri and client are trusted — redirect back with error for all remaining failures

	// Reject request objects — not supported (OIDC Core §6.1 / OIDCC-3.1.2.6)
	if get("request") != "" {
		redirectWithError(w, r, request.RedirectURI, request.State, "request_not_supported", "request objects are not supported")
		return
	}

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

	if !client.IsResponseTypeAllowed(registeredClient, request.ResponseType) {
		slog.Warn("authorize: invalid response_type for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "response_type", request.ResponseType)
		redirectWithError(w, r, request.RedirectURI, request.State, "unsupported_response_type", "response_type not allowed for this client")
		return
	}

	if !client.ValidateScopes(registeredClient, request.Scope) {
		slog.Warn("authorize: invalid scope for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "scope", request.Scope)
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_scope", "one or more requested scopes are not allowed for this client")
		return
	}

	// OIDC Core §3.1.2.1: prompt=login requires fresh authentication — skip SSO auto-login
	// OIDC Core §3.1.2.1: prompt=consent requires user consent — skip SSO auto-login
	cfg := config.Get()
	autoLoginResult := tryAutoLogin(r, cfg, request, registeredClient)
	if autoLoginResult.redirectURL != "" {
		http.Redirect(w, r, autoLoginResult.redirectURL, http.StatusFound)
		return
	}
	if autoLoginResult.needsConsent {
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

	// OIDC Core §3.1.2.1: prompt=none — return error if login or consent is required
	if request.Prompt == "none" {
		if autoLoginResult.hasSession {
			// OIDC Core §3.1.2.1: consent_required if consent is needed but prompt=none
			if consent.NeedsConsent(registeredClient.ConsentRequired, autoLoginResult.userID, request.ClientID, request.Scope, "") {
				redirectWithError(w, r, request.RedirectURI, request.State, "consent_required", "")
				return
			}
		}
		redirectWithError(w, r, request.RedirectURI, request.State, "login_required", "")
		return
	}

	// OIDC Core §3.1.2.1: prompt=create signals the client wants the registration form
	if request.Prompt == "create" {
		if !config.Get().AuthAllowSelfSignup {
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
		}, get("error"))
		return
	}

	// If the authorize request arrived as POST, redirect to GET so that the CSRF
	// middleware runs and sets the CSRF cookie before rendering the login form.
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
		http.Redirect(w, r, "/oauth2/authorize?"+q.Encode(), http.StatusFound)
		return
	}

	renderLogin(w, r, request, get("error"))
}

// renderLogin renders the login form, or an error-only page when errorMsg is a fatal
// configuration problem (e.g. invalid redirect URI) where submitting the form makes no sense.
func renderLogin(w http.ResponseWriter, r *http.Request, request AuthorizeRequest, errorMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("login")
	if err != nil {
		slog.Error("authorize: failed to parse login template", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	federatedProviders, _ := federation.ListEnabledProviderViews()

	data := map[string]any{
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
		"AllowSelfSignup":     cfg.AuthAllowSelfSignup,
		"ProfileFieldEmail":   cfg.ProfileFieldEmail,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeTagline":        cfg.Theme.Tagline,
		"SmtpConfigured":      cfg.SmtpHost != "",
		"FederatedProviders":  federatedProviders,
	}

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("authorize: failed to execute login template", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// redirectWithError redirects back to the redirect_uri with OAuth2 error params.
// Per RFC 6749 §4.1.2.1 and Appendix B, all query values are percent-encoded.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	q := url.Values{}
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	http.Redirect(w, r, redirectURI+"?"+q.Encode(), http.StatusFound)
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

	if !cfg.AuthSsoEnabled || hasLogin {
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

	withinIdleTimeout := cfg.AuthSsoSessionIdleTimeout == 0 || time.Since(session.LastActivityAt) < cfg.AuthSsoSessionIdleTimeout
	if !withinIdleTimeout {
		return autoLoginResult{hasSession: true, userID: session.UserID}
	}

	withinMaxAge := cfg.AuthSsoSessionMaxAge == 0 || time.Since(session.CreatedAt) < cfg.AuthSsoSessionMaxAge
	if !withinMaxAge {
		return autoLoginResult{hasSession: true, userID: session.UserID}
	}

	maxAgeSecs := parseMaxAge(request.MaxAge)
	if maxAgeSecs >= 0 && time.Since(session.CreatedAt) > time.Duration(maxAgeSecs)*time.Second {
		return autoLoginResult{hasSession: true, userID: session.UserID}
	}

	_ = idpsession.UpdateLastActivity(session.ID)

	// OIDC Core §3.1.2.4: check consent before issuing auth code
	if hasConsent || consent.NeedsConsent(registeredClient.ConsentRequired, session.UserID, request.ClientID, request.Scope, request.Prompt) {
		return autoLoginResult{needsConsent: true, hasSession: true, userID: session.UserID}
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
	redirectParams := url.Values{}
	redirectParams.Set("code", ac.Code)
	if request.State != "" {
		redirectParams.Set("state", request.State)
	}
	return autoLoginResult{redirectURL: request.RedirectURI + "?" + redirectParams.Encode(), hasSession: true, userID: session.UserID}
}

// parseMaxAge parses the max_age query parameter as seconds.
// Returns -1 if absent or invalid (meaning no max_age constraint).
func parseMaxAge(s string) int64 {
	if s == "" {
		return -1
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return -1
	}
	return v
}

// renderError renders a branded error page without any login form fields.
// Use this for fatal errors where redirecting or submitting credentials makes no sense.
func renderError(w http.ResponseWriter, errorMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("error")
	if err != nil {
		slog.Error("authorize: failed to parse error template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Error":        errorMsg,
		"ThemeTitle":   cfg.Theme.Title,
		"ThemeLogoUrl": cfg.Theme.LogoUrl,
	}

	w.WriteHeader(http.StatusBadRequest)
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
