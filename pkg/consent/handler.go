package consent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/reqid"
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

func handleConsentGet(w http.ResponseWriter, r *http.Request) {
	params := parseConsentParams(r)

	session, userID := validateSession(w, r)
	if session == nil {
		return
	}

	registeredClient, err := client.ClientByClientID(params.ClientID)
	if err != nil {
		slog.Warn("consent: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
		return
	}

	renderConsentPage(w, r, params, registeredClient.ClientName, userID)
}

func handleConsentPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	params := ConsentParams{
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		ClientID:            r.FormValue("client_id"),
		Scope:               r.FormValue("scope"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		Prompt:              r.FormValue("prompt"),
	}

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

	registeredClient, err := client.ClientByClientID(params.ClientID)
	if err != nil {
		slog.Warn("consent: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
		return
	}

	if !client.IsValidRedirectURI(registeredClient, params.RedirectURI) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Redirect URI not allowed for this client")
		return
	}

	action := r.FormValue("action")

	// RFC 6749 §4.1.2.1: access_denied — the resource owner denied the request
	if action == "deny" {
		q := url.Values{}
		q.Set("error", "access_denied")
		q.Set("error_description", "The resource owner denied the request")
		if params.State != "" {
			q.Set("state", params.State)
		}
		http.Redirect(w, r, params.RedirectURI+"?"+q.Encode(), http.StatusFound)
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

	cfg := config.Get()
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
	}

	if err := authcode.CreateAuthCode(ac); err != nil {
		slog.Error("consent: failed to create auth code", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Something went wrong")
		return
	}

	redirectParams := url.Values{}
	redirectParams.Set("code", ac.Code)
	if params.State != "" {
		redirectParams.Set("state", params.State)
	}
	http.Redirect(w, r, params.RedirectURI+"?"+redirectParams.Encode(), http.StatusFound)
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
		"ConsentSig":          signConsent(params, userID),
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
	}

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("consent: failed to execute template", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// RedirectToConsent builds a redirect URL to the consent screen with all OAuth params preserved.
func RedirectToConsent(w http.ResponseWriter, r *http.Request, params ConsentParams) {
	q := url.Values{}
	q.Set("client_id", params.ClientID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("scope", params.Scope)
	q.Set("state", params.State)
	q.Set("nonce", params.Nonce)
	q.Set("code_challenge", params.CodeChallenge)
	q.Set("code_challenge_method", params.CodeChallengeMethod)
	q.Set("prompt", params.Prompt)
	consentURL := config.GetBootstrap().AppOAuthPath + "/consent?" + q.Encode()
	http.Redirect(w, r, consentURL, http.StatusFound)
}

func parseConsentParams(r *http.Request) ConsentParams {
	return ConsentParams{
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		State:               r.URL.Query().Get("state"),
		ClientID:            r.URL.Query().Get("client_id"),
		Scope:               r.URL.Query().Get("scope"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		Prompt:              r.URL.Query().Get("prompt"),
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

func signConsent(params ConsentParams, userID string) string {
	data := strings.Join([]string{
		userID,
		params.ClientID,
		params.RedirectURI,
		params.Scope,
		params.Nonce,
		params.CodeChallenge,
		params.CodeChallengeMethod,
		params.State,
	}, "\n")
	secret := []byte(config.GetBootstrap().AuthCSRFProtectionSecretKey)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyConsentSignature(params ConsentParams, userID, signature string) bool {
	expected := signConsent(params, userID)
	return hmac.Equal([]byte(expected), []byte(signature))
}
