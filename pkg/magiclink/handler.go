package magiclink

import (
	"database/sql"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/email"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

type oauthParams struct {
	RedirectURI         string
	State               string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func paramsFromQuery(r *http.Request) oauthParams {
	q := r.URL.Query()
	return oauthParams{
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		ClientID:            q.Get("client_id"),
		Scope:               q.Get("scope"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
}

func paramsFromForm(r *http.Request) oauthParams {
	return oauthParams{
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		ClientID:            r.FormValue("client_id"),
		Scope:               r.FormValue("scope"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}
}

func renderMagicLink(w http.ResponseWriter, r *http.Request, mode string, params oauthParams, authorizeSig, errMsg string, extra map[string]any) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("magic_link")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Mode":                mode,
		"RedirectURI":         params.RedirectURI,
		"State":               params.State,
		"ClientID":            params.ClientID,
		"Scope":               params.Scope,
		"Nonce":               params.Nonce,
		"CodeChallenge":       params.CodeChallenge,
		"CodeChallengeMethod": params.CodeChallengeMethod,
		"AuthorizeSig":        authorizeSig,
		"Error":               errMsg,
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		csrf.TemplateTag:      csrf.TemplateField(r),
	}
	for k, v := range extra {
		data[k] = v
	}
	view.InjectNonce(r, data)
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// HandleMagicLink handles GET and POST for /oauth2/magic-link.
// GET renders the email entry form. POST generates a magic link token and sends the email.
func HandleMagicLink(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if !cfg.MagicLinkEnabled {
		view.RenderError(w, r, http.StatusNotFound, "Magic link login is not enabled.")
		return
	}
	if cfg.SmtpHost == "" {
		view.RenderError(w, r, http.StatusServiceUnavailable, "Email is not configured.")
		return
	}

	if r.Method == http.MethodGet {
		params := paramsFromQuery(r)
		// RFC 6749 §4.1.1 / §10.6: signing parameters must not authorize an arbitrary client or redirect.
		if _, err := client.ValidateAuthorization(params.authorizeParams()); err != nil {
			view.RenderError(w, r, http.StatusBadRequest, err.Error())
			return
		}
		sig := authzsig.Sign(params.authorizeParams())
		renderMagicLink(w, r, "form", params, sig, "", nil)
		return
	}

	// POST
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	params := paramsFromForm(r)
	authorizeSigValue := r.FormValue("authorize_sig")
	emailAddr := r.FormValue("email")

	if emailAddr == "" {
		renderMagicLink(w, r, "form", params, authorizeSigValue, "Please enter your email address.", nil)
		return
	}

	sentExtra := map[string]any{"Email": emailAddr}

	// RFC 6749 §10.6: validate integrity and registration before sending credentials.
	if _, err := validateSignedAuthorization(params, authorizeSigValue); err != nil {
		slog.Warn("magiclink: invalid authorization request", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID, "ip", utils.GetClientIP(r), "error", err)
		view.RenderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	utils.RandomDelay()

	reqID := reqid.Get(r.Context())

	// Look up user by verified email only
	usr, err := user.UserByEmail(emailAddr)
	if err != nil || usr == nil || usr.DeactivatedAt != nil {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}

	rawToken, tokenHash, err := generateToken()
	if err != nil {
		slog.Error("magiclink: failed to generate token", "request_id", reqID, "error", err)
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}

	code, err := generateCode()
	if err != nil {
		slog.Error("magiclink: failed to generate code", "request_id", reqID, "error", err)
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}
	codeHash := utils.HashSHA256(code)

	expiresAt, err := issueMagicLinkToken(usr.ID, tokenHash, codeHash, time.Now().Add(cfg.MagicLinkExpiration))
	if err != nil {
		if !errors.Is(err, errIssuanceSuppressed) {
			slog.Error("magiclink: failed to store token", "request_id", reqID, "error", err)
		}
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}

	audit.Log(audit.EventMagicLinkRequested, nil, audit.TargetUser, usr.ID, nil, utils.GetClientIP(r))

	magicLinkURL := buildMagicLinkURL(rawToken, params, authorizeSigValue)
	expirationMinutes := max(int(math.Ceil(time.Until(expiresAt).Minutes())), 1)
	go func() {
		if err := email.SendMagicLinkEmail(usr.Email, magicLinkURL, code, expirationMinutes); err != nil {
			slog.Error("magiclink: failed to send email", "request_id", reqID, "error", err)
		}
	}()

	renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
}

// HandleMagicLinkVerify handles GET for /oauth2/magic-link/verify.
// Validates the magic link token and completes the login flow.
func HandleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if !cfg.MagicLinkEnabled {
		view.RenderError(w, r, http.StatusNotFound, "Magic link login is not enabled.")
		return
	}

	params := paramsFromQuery(r)
	authorizeSigValue := r.URL.Query().Get("authorize_sig")
	rawToken := r.URL.Query().Get("token")

	if rawToken == "" {
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "Invalid or missing magic link.", nil)
		return
	}

	tokenHash := utils.HashSHA256(rawToken)
	userID, expiresAt, usedAt, err := getMagicLinkTokenInfo(tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			renderMagicLink(w, r, "expired", params, authorizeSigValue, "This magic link is invalid or has already been used.", nil)
			return
		}
		slog.Error("magiclink: failed to look up token", "request_id", reqid.Get(r.Context()), "error", err)
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "Something went wrong. Please request a new link.", nil)
		return
	}

	if usedAt != nil {
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "This magic link has already been used.", nil)
		return
	}

	if time.Now().After(expiresAt) {
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "This magic link has expired.", nil)
		return
	}

	// RFC 6749 §10.6: invalid authorization must not consume a valid login credential.
	if _, err := validateSignedAuthorization(params, authorizeSigValue); err != nil {
		slog.Warn("magiclink: invalid authorization request", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID, "ip", utils.GetClientIP(r), "error", err)
		view.RenderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	if err := consumeMagicLinkToken(tokenHash); err != nil {
		if err == sql.ErrNoRows {
			renderMagicLink(w, r, "expired", params, authorizeSigValue, "This magic link is invalid or has already been used.", nil)
		} else {
			slog.Error("magiclink: failed to consume token", "request_id", reqid.Get(r.Context()), "error", err)
			renderMagicLink(w, r, "expired", params, authorizeSigValue, "Something went wrong. Please request a new link.", nil)
		}
		return
	}

	completeLogin(w, r, params, authorizeSigValue, userID)
}

// HandleMagicLinkVerifyCode handles POST for /oauth2/magic-link/verify.
// Validates the 6-digit code and completes the login flow.
func HandleMagicLinkVerifyCode(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if !cfg.MagicLinkEnabled {
		view.RenderError(w, r, http.StatusNotFound, "Magic link login is not enabled.")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	params := paramsFromForm(r)
	authorizeSigValue := r.FormValue("authorize_sig")
	emailAddr := r.FormValue("email")
	code := r.FormValue("code")
	sentExtra := map[string]any{"Email": emailAddr}

	if code == "" {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "Please enter the code from your email.", sentExtra)
		return
	}

	utils.RandomDelay()

	genericErr := "Invalid code. Please check and try again."
	usr, err := user.UserByEmail(emailAddr)
	if err != nil || usr == nil {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	tokenHash, codeHash, expiresAt, failedAttempts, err := getLatestUnusedMagicLinkToken(usr.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
			return
		}
		slog.Error("magiclink: failed to look up code", "request_id", reqid.Get(r.Context()), "error", err)
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	if time.Now().After(expiresAt) || failedAttempts >= maxCodeAttempts {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	if utils.HashSHA256(code) != codeHash {
		attempts, err := recordFailedCodeAttempt(tokenHash)
		if err != nil && err != sql.ErrNoRows {
			slog.Error("magiclink: failed to record invalid code attempt", "request_id", reqid.Get(r.Context()), "error", err)
		}
		if err == nil && attempts == maxCodeAttempts {
			audit.Log(audit.EventLoginFailed, nil, audit.TargetUser, usr.ID,
				audit.Detail("method", "magic_link", "reason", "code_attempts_exhausted"), utils.GetClientIP(r))
		}
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	// RFC 6749 §10.6: invalid authorization must not consume a valid login credential.
	if _, err := validateSignedAuthorization(params, authorizeSigValue); err != nil {
		slog.Warn("magiclink: invalid authorization request", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID, "ip", utils.GetClientIP(r), "error", err)
		view.RenderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	if err := consumeMagicLinkToken(tokenHash); err != nil {
		if err != sql.ErrNoRows {
			slog.Error("magiclink: failed to consume code", "request_id", reqid.Get(r.Context()), "error", err)
		}
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	completeLogin(w, r, params, authorizeSigValue, usr.ID)
}

// completeLogin performs the post-verification login flow: signature check,
// client validation, MFA, consent, IdP session, and auth code issuance.
func completeLogin(w http.ResponseWriter, r *http.Request, params oauthParams, authorizeSigValue, userID string) {
	// RFC 6749 §10.6: re-check the current registration before issuance.
	_, err := validateSignedAuthorization(params, authorizeSigValue)
	if err != nil {
		slog.Warn("magiclink: invalid authorization request", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID, "ip", utils.GetClientIP(r), "error", err)
		view.RenderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	// OIDC Core §3.1.2.3–4: email proof does not bypass local TOTP or consent.
	nextURL, err := mfa.FinishLogin(w, r, userID, mfa.LoginState{
		RedirectURI:         params.RedirectURI,
		State:               params.State,
		ClientID:            params.ClientID,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
	}, mfa.PrimaryMagicLink)
	if err != nil {
		slog.Error("magiclink: failed to complete authentication", "request_id", reqid.Get(r.Context()), "error", err)
		view.RenderError(w, r, http.StatusServiceUnavailable, "Login could not be completed. Please sign in again.")
		return
	}
	// RFC 6749 §4.1.2: follow the validated next authentication step.
	http.Redirect(w, r, nextURL, http.StatusFound)
}

func buildMagicLinkURL(rawToken string, p oauthParams, authorizeSig string) string {
	bs := config.GetBootstrap()
	q := url.Values{}
	q.Set("token", rawToken)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("state", p.State)
	q.Set("client_id", p.ClientID)
	q.Set("scope", p.Scope)
	q.Set("authorize_sig", authorizeSig)
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}
	if p.CodeChallenge != "" {
		q.Set("code_challenge", p.CodeChallenge)
		q.Set("code_challenge_method", p.CodeChallengeMethod)
	}
	return bs.AppURL + bs.AppOAuthPath + "/magic-link/verify?" + q.Encode()
}

func (p oauthParams) authorizeParams() authzsig.AuthorizeParams {
	return authzsig.AuthorizeParams{ClientID: p.ClientID, RedirectURI: p.RedirectURI, Scope: p.Scope, Nonce: p.Nonce,
		State: p.State, CodeChallenge: p.CodeChallenge, CodeChallengeMethod: p.CodeChallengeMethod}
}

func validateSignedAuthorization(p oauthParams, signature string) (*client.Client, error) {
	// RFC 6749 §10.6: integrity is necessary but does not authorize a redirect or scope.
	params := p.authorizeParams()
	if !authzsig.Verify(params, signature) {
		return nil, errors.New("authorization request parameters have been tampered with")
	}
	return client.ValidateAuthorization(params)
}
