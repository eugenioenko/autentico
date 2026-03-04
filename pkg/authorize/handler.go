package authorize

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/appsettings"
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
	q := r.URL.Query()

	request := AuthorizeRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Prompt:              q.Get("prompt"),
	}

	err := ValidateAuthorizeRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_request", err.Error())
		return
	}

	// Enforce S256 — reject plain per RFC 7636 §4.2 ("SHOULD NOT be used")
	if request.CodeChallengeMethod == "plain" && config.Get().AuthPKCEEnforceSHA256 {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "code_challenge_method 'plain' is not allowed; use S256")
		return
	}

	// Support prompt=signup to automatically go to the signup/onboarding page while preserving OIDC state
	if request.Prompt == "signup" {
		target := "/signup"
		if !appsettings.IsOnboarded() {
			target = "/onboard"
		}
		destURL := config.GetBootstrap().AppOAuthPath + target + "?" + q.Encode()
		http.Redirect(w, r, destURL, http.StatusFound)
		return
	}

	// Validate redirect_uri format
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		renderError(w, "Invalid redirect_uri")
		return
	}

	// Validate client_id against registered clients
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

	if !client.IsResponseTypeAllowed(registeredClient, request.ResponseType) {
		slog.Warn("authorize: invalid response_type for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "response_type", request.ResponseType)
		renderError(w, "Response type not allowed for this client")
		return
	}

	if !client.ValidateScopes(registeredClient, request.Scope) {
		slog.Warn("authorize: invalid scope for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "scope", request.Scope)
		renderError(w, "One or more requested scopes are not allowed for this client")
		return
	}

	// Check for valid IdP session (auto-login)
	cfg := config.Get()
	if cfg.AuthSsoSessionIdleTimeout > 0 {
		sessionID := idpsession.ReadCookie(r)
		if sessionID != "" {
			session, err := idpsession.IdpSessionByID(sessionID)
			if err == nil && time.Since(session.LastActivityAt) < cfg.AuthSsoSessionIdleTimeout {
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

	if request.Prompt == "none" {
		redirectURL := fmt.Sprintf("%s?error=login_required&state=%s", request.RedirectURI, request.State)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	renderLogin(w, r, request, q.Get("error"))
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
