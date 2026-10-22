package emailverification

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"time"

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

// OAuthParams holds the OAuth2 authorization request parameters needed to
// resume the flow after email verification.
type OAuthParams struct {
	RedirectURI         string
	State               string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
	AuthorizeSig        string
}

// GenerateToken returns a URL-safe random token and its SHA-256 hash.
func GenerateToken() (rawToken, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	rawToken = base64.RawURLEncoding.EncodeToString(b)
	tokenHash = utils.HashSHA256(rawToken)
	return
}

// BuildVerifyURL constructs the full verification link to embed in the email.
func BuildVerifyURL(rawToken string, p OAuthParams) string {
	bs := config.GetBootstrap()
	q := url.Values{}
	q.Set("token", rawToken)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("state", p.State)
	q.Set("prompt", p.Prompt)
	q.Set("max_age", p.MaxAge)
	q.Set("client_id", p.ClientID)
	q.Set("scope", p.Scope)
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}
	if p.CodeChallenge != "" {
		q.Set("code_challenge", p.CodeChallenge)
		q.Set("code_challenge_method", p.CodeChallengeMethod)
	}
	if p.AuthorizeSig != "" {
		q.Set("authorize_sig", p.AuthorizeSig)
	}
	return bs.AppURL + bs.AppOAuthPath + "/verify-email?" + q.Encode()
}

// RenderVerifyEmail renders the verify_email template.
// mode: "sent" (after signup/resend), "blocked" (login attempt), "expired" (stale link).
func RenderVerifyEmail(w http.ResponseWriter, r *http.Request, mode, username string, params OAuthParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("verify_email")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Mode":                mode,
		"Username":            username,
		"RedirectURI":         params.RedirectURI,
		"State":               params.State,
		"ClientID":            params.ClientID,
		"Scope":               params.Scope,
		"Nonce":               params.Nonce,
		"CodeChallenge":       params.CodeChallenge,
		"CodeChallengeMethod": params.CodeChallengeMethod,
		"AuthorizeSig":        params.AuthorizeSig,
		"Error":               errMsg,
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"Prompt":              params.Prompt,
		"LoginPrompt":         client.LoginPrompt(params.Prompt),
		"MaxAge":              params.MaxAge,
	}
	view.InjectNonce(r, data)
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// HandleVerifyEmail handles GET /oauth2/verify-email?token=...&<oauth params>
func HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	rawToken := r.URL.Query().Get("token")
	if rawToken == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	params := OAuthParams{
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		State:               r.URL.Query().Get("state"),
		ClientID:            r.URL.Query().Get("client_id"),
		Scope:               r.URL.Query().Get("scope"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		AuthorizeSig:        r.URL.Query().Get("authorize_sig"),
		Prompt:              r.URL.Query().Get("prompt"),
		MaxAge:              r.URL.Query().Get("max_age"),
	}

	// Verify HMAC signature to prevent authorize parameter tampering (#184, #186)
	if !authzsig.Verify(authzsig.AuthorizeParams{
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		State:               params.State,
		Prompt:              params.Prompt,
		MaxAge:              params.MaxAge,
	}, params.AuthorizeSig) {
		slog.Warn("verify-email: authorize parameter signature mismatch")
		RenderVerifyEmail(w, r, "expired", "", params, "Invalid verification link. Please log in again.")
		return
	}

	// RFC 6749 §4.1.1 / §10.6: a valid signature is not a registration check.
	// Reject before consuming the verification token or creating a session.
	_, err := client.ValidateAuthorization(authzsig.FromValues(r.URL.Query()))
	if err != nil {
		view.RenderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	tokenHash := utils.HashSHA256(rawToken)
	userID, expiresAt, err := user.GetVerificationTokenInfo(tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			RenderVerifyEmail(w, r, "expired", "", params, "This verification link is invalid or has already been used.")
			return
		}
		slog.Error("verify-email: failed to look up token", "request_id", reqid.Get(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "expired", "", params, "Something went wrong. Please request a new verification link.")
		return
	}

	if time.Now().After(expiresAt) {
		usr, _ := user.UserByID(userID)
		username := ""
		if usr != nil {
			username = usr.Username
		}
		RenderVerifyEmail(w, r, "expired", username, params, "This verification link has expired.")
		return
	}

	if err := user.MarkEmailVerified(userID); err != nil {
		slog.Error("verify-email: failed to mark email verified", "request_id", reqid.Get(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "expired", "", params, "Something went wrong. Please request a new verification link.")
		return
	}

	// OIDC Core §3.1.2.3–4: email ownership cannot bypass local TOTP or consent.
	nextURL, err := mfa.FinishLogin(w, r, userID, mfa.LoginState{
		RedirectURI:         params.RedirectURI,
		State:               params.State,
		ClientID:            params.ClientID,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Prompt:              params.Prompt,
		MaxAge:              params.MaxAge,
	}, mfa.PrimaryVerification)
	if err != nil {
		slog.Error("verify-email: failed to complete authentication", "request_id", reqid.Get(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "expired", "", params, "Verification succeeded but login failed. Please log in manually.")
		return
	}
	// RFC 6749 §4.1.2: follow the validated next authentication step.
	http.Redirect(w, r, nextURL, http.StatusFound)
}

// Eight detached resend deliveries may be outstanding per process. Admission
// never blocks the public response or invalidates an existing link on overload.
var verificationDeliveries = make(chan struct{}, 8)

// HandleResendVerification handles POST /oauth2/resend-verification
func HandleResendVerification(w http.ResponseWriter, r *http.Request) {
	handleResendVerification(w, r, email.SendVerificationEmail, verificationDeliveries)
}

// handleResendVerification starts the supplied sender after storing a validated
// link. Delivery runs independently of the generic HTTP response.
func handleResendVerification(w http.ResponseWriter, r *http.Request, send func(string, string) error, inFlight chan struct{}) {
	if err := r.ParseForm(); err != nil {
		RenderVerifyEmail(w, r, "expired", "", OAuthParams{}, "Invalid request. Please try again.")
		return
	}

	username := r.FormValue("username")
	params := OAuthParams{
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		ClientID:            r.FormValue("client_id"),
		Scope:               r.FormValue("scope"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		AuthorizeSig:        r.FormValue("authorize_sig"),
		Prompt:              r.FormValue("prompt"),
		MaxAge:              r.FormValue("max_age"),
	}

	// RFC 6749 §10.6: never email a verification link with unvalidated authorization parameters.
	signedParams := authzsig.FromValues(r.Form)
	if !authzsig.Verify(signedParams, params.AuthorizeSig) {
		view.RenderError(w, r, http.StatusBadRequest, "Authorization request parameters have been tampered with")
		return
	}
	if _, err := client.ValidateAuthorization(signedParams); err != nil {
		view.RenderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	// OWASP Authentication §Authentication Responses / Forgot Password
	// §Forgot Password Request: use the same response and delay policy for all
	// accepted requests, including unknown, verified and undeliverable accounts.
	utils.RandomDelay()
	defer RenderVerifyEmail(w, r, "sent", username, params, "")

	usr, err := user.UserByUsername(username)
	if err != nil || usr == nil || usr.IsEmailVerified || usr.Email == "" {
		return
	}

	reqID := reqid.Get(r.Context())
	cfg := config.Get()
	if cfg.SmtpHost == "" {
		slog.Error("resend-verification: SMTP is not configured", "request_id", reqID)
		return
	}
	// OWASP Forgot Password §Forgot Password Request: bound background work
	// without revealing overload, waiting for SMTP or replacing an unsent link.
	select {
	case inFlight <- struct{}{}:
	default:
		slog.Warn("resend-verification: delivery capacity reached", "request_id", reqID)
		return
	}
	transferred := false
	defer func() {
		if !transferred {
			<-inFlight
		}
	}()
	rawToken, tokenHash, err := GenerateToken()
	if err != nil {
		slog.Error("resend-verification: failed to generate token", "request_id", reqID, "error", err)
		return
	}

	expiresAt := time.Now().Add(cfg.EmailVerificationExpiration)
	if err := user.SetEmailVerificationToken(usr.ID, tokenHash, expiresAt); err != nil {
		slog.Error("resend-verification: failed to store token", "request_id", reqID, "error", err)
		return
	}

	verifyURL := BuildVerifyURL(rawToken, params)
	to := usr.Email
	// OWASP Forgot Password §Forgot Password Request: SMTP latency must not
	// distinguish deliverable accounts. Capture values, not the HTTP request.
	transferred = true
	go func() {
		defer func() { <-inFlight }()
		if err := send(to, verifyURL); err != nil {
			slog.Error("resend-verification: failed to send email", "request_id", reqID, "error", err)
		}
	}()
}
