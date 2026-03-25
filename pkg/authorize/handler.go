package authorize

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"

	"github.com/gorilla/csrf"
)

// HandleAuthorize godoc
// @Summary Authorize a client
// @Description Handles the authorization request and displays the login page
// @Tags authorize
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
		slog.Warn("authorize: unknown client_id", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		renderError(w, "Unknown client_id")
		return
	}

	if !registeredClient.IsActive {
		slog.Warn("authorize: inactive client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r))
		renderError(w, "Client is inactive")
		return
	}

	if !client.IsValidRedirectURI(registeredClient, request.RedirectURI) {
		slog.Warn("authorize: invalid redirect_uri for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "redirect_uri", request.RedirectURI)
		renderError(w, "Redirect URI not allowed for this client")
		return
	}

	// From here redirect_uri and client are trusted — redirect back with error for all remaining failures

	if err := ValidateAuthorizeRequest(request); err != nil {
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_request", err.Error())
		return
	}

	// Enforce S256 — reject plain per RFC 7636 §4.2 ("SHOULD NOT be used")
	if request.CodeChallengeMethod == "plain" && config.Get().AuthPKCEEnforceSHA256 {
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_request", "code_challenge_method 'plain' is not allowed; use S256")
		return
	}

	if !client.IsResponseTypeAllowed(registeredClient, request.ResponseType) {
		slog.Warn("authorize: invalid response_type for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "response_type", request.ResponseType)
		redirectWithError(w, r, request.RedirectURI, request.State, "unsupported_response_type", "response_type not allowed for this client")
		return
	}

	if !client.ValidateScopes(registeredClient, request.Scope) {
		slog.Warn("authorize: invalid scope for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "scope", request.Scope)
		redirectWithError(w, r, request.RedirectURI, request.State, "invalid_scope", "one or more requested scopes are not allowed for this client")
		return
	}

	// Check for valid IdP session (auto-login)
	// prompt=login requires fresh authentication — skip SSO auto-login
	// max_age requires re-authentication if session is older than max_age seconds
	cfg := config.Get()
	maxAgeSecs := parseMaxAge(request.MaxAge)
	if cfg.AuthSsoSessionIdleTimeout > 0 && request.Prompt != "login" {
		sessionID := idpsession.ReadCookie(r)
		if sessionID != "" {
			session, err := idpsession.IdpSessionByID(sessionID)
			if err == nil {
				sessionAge := time.Since(session.CreatedAt)
				maxAgeExceeded := maxAgeSecs >= 0 && sessionAge > time.Duration(maxAgeSecs)*time.Second
				if time.Since(session.LastActivityAt) < cfg.AuthSsoSessionIdleTimeout && !maxAgeExceeded {
					// Valid IdP session — auto-login
					_ = idpsession.UpdateLastActivity(session.ID)

					code, err := authcode.GenerateSecureCode()
					if err == nil {
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
						}
						if authcode.CreateAuthCode(ac) == nil {
							redirectURL := fmt.Sprintf("%s?code=%s&state=%s", request.RedirectURI, ac.Code, request.State)
							http.Redirect(w, r, redirectURL, http.StatusFound)
							return
						}
					}
				}
			}
		}
	}

	if request.Prompt == "none" {
		redirectURL := fmt.Sprintf("%s?error=login_required&state=%s", request.RedirectURI, request.State)
		http.Redirect(w, r, redirectURL, http.StatusFound)
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
		slog.Error("authorize: failed to parse login template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
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
		"Error":               errorMsg,
		"AuthMode":            cfg.AuthMode,
		"AllowSelfSignup":     cfg.AuthAllowSelfSignup,
		"ProfileFieldEmail":   cfg.ProfileFieldEmail,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeCssResolved":    template.CSS(cfg.ThemeCssResolved),
		"FederatedProviders":  federatedProviders,
	}

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("authorize: failed to execute login template", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// redirectWithError redirects back to the redirect_uri with OAuth2 error params.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	u := fmt.Sprintf("%s?error=%s&error_description=%s", redirectURI, errCode, errDesc)
	if state != "" {
		u += "&state=" + state
	}
	http.Redirect(w, r, u, http.StatusFound)
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
		"Error":            errorMsg,
		"ThemeTitle":       cfg.Theme.Title,
		"ThemeLogoUrl":     cfg.Theme.LogoUrl,
		"ThemeCssResolved": template.CSS(cfg.ThemeCssResolved),
	}

	w.WriteHeader(http.StatusBadRequest)
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
