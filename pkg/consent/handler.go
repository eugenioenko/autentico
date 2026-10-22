package consent

import (
	"crypto/hmac"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

type ConsentParams struct {
	RedirectURI         string
	State               string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
	FlowToken           string
}

func HandleConsent(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleConsentGet(w, r)
	case http.MethodPost:
		handleConsentPost(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

// handleConsentGet requires session MFA evidence before rendering consent.
func handleConsentGet(w http.ResponseWriter, r *http.Request) {
	params := parseConsentParams(r)

	session, userID := validateSession(w, r)
	if session == nil {
		return
	}

	// RFC 6749 §3.1.2 / §3.3 / §4.1.1 and RFC 7636 §4.4.1:
	// public GET cannot sign a request outside the current client registration.
	registeredClient, err := client.ValidateAuthorization(params.authorization())
	if err != nil {
		slog.Warn("consent: invalid authorization request", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if !validateContinuation(w, params, session, registeredClient) {
		return
	}
	renderConsentPage(w, r, params, registeredClient.ClientName, userID)
}

// handleConsentPost revalidates the signed request and current MFA policy before persisting consent or issuing a code.
func handleConsentPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	params := paramsFromValues(r.PostForm)

	session, userID := validateSession(w, r)
	if session == nil {
		return
	}

	// Verify consent signature to prevent parameter tampering
	consentSig := r.FormValue("consent_sig")
	if !verifyConsentSignature(params, userID, consentSig) {
		slog.Warn("consent: signature mismatch", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID, "ip", utils.GetClientIP(r))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Consent parameters have been tampered with")
		return
	}

	// RFC 6749 §3.1.2 / §3.3 / §4.1.1 and RFC 9700 §2.1.1:
	// a signed consent page cannot override changed registration or PKCE policy.
	registeredClient, err := client.ValidateAuthorization(params.authorization())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if !validateContinuation(w, params, session, registeredClient) {
		return
	}

	// RFC 6749 §3.1.2: retain the registered callback's query on both outcomes.
	redirectURL, err := url.Parse(params.RedirectURI)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	action := r.PostForm.Get("action")
	// OIDC Core §3.1.2.4: an explicit authorization decision is required.
	if action != "allow" && action != "deny" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Choose whether to allow access")
		return
	}

	// RFC 6749 §4.1.2.1: access_denied — the resource owner denied the request
	if action == "deny" {
		q := redirectURL.Query()
		q.Set("error", "access_denied")
		q.Set("error_description", "The resource owner denied the request")
		if params.State != "" {
			q.Set("state", params.State)
		}
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}

	// OIDC Core §3.1.2.4: store consent for this user+client+scopes
	if err := UpsertConsent(userID, params.ClientID, params.Scope); err != nil {
		slog.Error("consent: failed to store consent", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store consent")
		return
	}

	// Generate authorization code and redirect
	code, err := authcode.GenerateSecureCode()
	if err != nil {
		slog.Error("consent: failed to generate auth code", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Something went wrong")
		return
	}

	cfg := config.GetForClient(registeredClient.ToOverrides())
	ac := authcode.AuthCode{
		Code:                code,
		UserID:              userID,
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
		Used:                false,
		IdpSessionID:        session.ID,
		CreatedAt:           session.CreatedAt,
	}

	if err := authcode.CreateAuthCode(ac); err != nil {
		slog.Error("consent: failed to create auth code", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Something went wrong")
		return
	}

	// RFC 6749 §4.1.2: authorization response MUST include code; state MUST be echoed unchanged if present
	redirectParams := redirectURL.Query()
	redirectParams.Set("code", ac.Code)
	if params.State != "" {
		redirectParams.Set("state", params.State)
	}
	redirectURL.RawQuery = redirectParams.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func renderConsentPage(w http.ResponseWriter, r *http.Request, params ConsentParams, clientName, userID string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("consent")
	if err != nil {
		slog.Error("consent: failed to parse template", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"ClientName":          clientName,
		"Scopes":              DescribeScopes(params.Scope),
		"State":               params.State,
		"RedirectURI":         params.RedirectURI,
		"ClientID":            params.ClientID,
		"Scope":               params.Scope,
		"Nonce":               params.Nonce,
		"CodeChallenge":       params.CodeChallenge,
		"CodeChallengeMethod": params.CodeChallengeMethod,
		"Prompt":              params.Prompt,
		"MaxAge":              params.MaxAge,
		"FlowToken":           params.FlowToken,
		"ConsentSig":          signConsent(params, userID),
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
	}
	view.InjectNonce(r, data)

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("consent: failed to execute template", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// RedirectToConsent builds a redirect URL to the consent screen with all OAuth params preserved.
func RedirectToConsent(w http.ResponseWriter, r *http.Request, params ConsentParams) {
	target, err := flowURL(params, idpsession.ReadCookie(r), flowSSO, time.Now())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "login_required", "Authentication required")
		return
	}
	// OIDC Core §3.1.2.4: only eligible SSO may request this consent continuation.
	http.Redirect(w, r, target, http.StatusFound)
}

// URL preserves the authorization parameters for HTML and JSON login flows.
func URL(params ConsentParams) string {
	return config.GetBootstrap().AppOAuthPath + "/consent?" + params.values().Encode()
}

func parseConsentParams(r *http.Request) ConsentParams {
	return paramsFromValues(r.URL.Query())
}

// paramsFromValues reads the signed authorization and continuation fields.
func paramsFromValues(values url.Values) ConsentParams {
	return ConsentParams{
		RedirectURI: values.Get("redirect_uri"), State: values.Get("state"), ClientID: values.Get("client_id"),
		Scope: values.Get("scope"), Nonce: values.Get("nonce"), CodeChallenge: values.Get("code_challenge"),
		CodeChallengeMethod: values.Get("code_challenge_method"),
		Prompt:              values.Get("prompt"),
		MaxAge:              values.Get("max_age"), FlowToken: values.Get("consent_flow"),
	}
}

// authorization preserves the registration-sensitive fields for shared validation.
func (params ConsentParams) authorization() authzsig.AuthorizeParams {
	return authzsig.AuthorizeParams{ClientID: params.ClientID, RedirectURI: params.RedirectURI, Scope: params.Scope,
		State: params.State, Nonce: params.Nonce, CodeChallenge: params.CodeChallenge, CodeChallengeMethod: params.CodeChallengeMethod,
		Prompt: params.Prompt,
		MaxAge: params.MaxAge,
	}
}

func validateSession(w http.ResponseWriter, r *http.Request) (*idpsession.IdpSession, string) {
	sessionID := idpsession.ReadCookie(r)
	if sessionID == "" {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "login_required", "Authentication required")
		return nil, ""
	}
	session, err := idpsession.IdpSessionByID(sessionID)
	if err != nil || session.DeactivatedAt != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "login_required", "Session expired")
		return nil, ""
	}
	return session, session.UserID
}

// validateMfa prevents direct consent from bypassing the local authentication policy.
func validateMfa(w http.ResponseWriter, session *idpsession.IdpSession, registered *client.Client) bool {
	cfg := config.GetForClient(registered.ToOverrides())
	usr, err := user.UserByID(session.UserID)
	// OIDC Core §3.1.2.3–4: consent cannot upgrade single-factor or legacy SSO.
	if err != nil || !idpsession.SatisfiesMfa(session.MfaMethod, usr, &cfg) {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "login_required", "Fresh authentication with MFA is required")
		return false
	}
	return true
}

// validateContinuation keeps public consent from upgrading an old session or
// signing an arbitrary new request, and rechecks policy again on approval.
func validateContinuation(w http.ResponseWriter, params ConsentParams, session *idpsession.IdpSession, registered *client.Client) bool {
	if !validateMfa(w, session, registered) {
		return false
	}
	cfg := config.GetForClient(registered.ToOverrides())
	now := time.Now()
	claims, err := verifyFlow(params, session, now)
	maxAge, ageErr := client.ParseMaxAge(params.MaxAge)
	// OIDC Core §3.1.2.1 / §3.1.2.3: consent cannot extend an expired login.
	if err != nil || ageErr != nil || !idpsession.IsFresh(session, &cfg, now) {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "login_required", "Sign-in expired. Please start again.")
		return false
	}
	var promptLogin, promptConsent, promptNone bool
	for _, prompt := range strings.Fields(params.Prompt) {
		promptLogin = promptLogin || prompt == "login"
		promptConsent = promptConsent || prompt == "consent"
		promptNone = promptNone || prompt == "none"
	}
	// OIDC Core §3.1.2.1: only proof of active login can satisfy prompt=login,
	// max_age=0, or the fresh-login continuation when SSO is disabled.
	if claims.Kind == flowSSO && (!cfg.AuthSsoEnabled || promptLogin || maxAge == 0) ||
		(maxAge > 0 && !idpsession.WithinMaxAge(session, maxAge, now)) {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "login_required", "Fresh authentication is required")
		return false
	}
	// OIDC Core §3.1.2.1 / §3.1.2.4: never interact for prompt=none or
	// manufacture a consent decision that neither client nor request needs.
	clientRequiresConsent := registered.ConsentRequired != nil && *registered.ConsentRequired
	if promptNone || !clientRequiresConsent && !promptConsent {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Consent is not requested for this authorization")
		return false
	}
	return true
}

// signConsent binds every displayed field and the continuation to its user.
func signConsent(params ConsentParams, userID string) string {
	values := params.values()
	values.Set("purpose", "consent-form-v2")
	values.Set("user_id", userID)
	return signValues(values)
}

func verifyConsentSignature(params ConsentParams, userID, signature string) bool {
	expected := signConsent(params, userID)
	return hmac.Equal([]byte(expected), []byte(signature))
}
