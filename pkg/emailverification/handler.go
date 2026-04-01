package emailverification

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/middleware"
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
	q.Set("client_id", p.ClientID)
	q.Set("scope", p.Scope)
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}
	if p.CodeChallenge != "" {
		q.Set("code_challenge", p.CodeChallenge)
		q.Set("code_challenge_method", p.CodeChallengeMethod)
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
		"Error":               errMsg,
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeCssResolved":    template.CSS(cfg.ThemeCssResolved),
		csrf.TemplateTag:      csrf.TemplateField(r),
	}
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
	}

	tokenHash := utils.HashSHA256(rawToken)
	userID, expiresAt, err := user.GetVerificationTokenInfo(tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			RenderVerifyEmail(w, r, "expired", "", params, "This verification link is invalid or has already been used.")
			return
		}
		slog.Error("verify-email: failed to look up token", "request_id", middleware.GetRequestID(r.Context()), "error", err)
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
		slog.Error("verify-email: failed to mark email verified", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "expired", "", params, "Something went wrong. Please request a new verification link.")
		return
	}

	// Issue auth code and redirect — user is now logged in
	authCodeStr, err := authcode.GenerateSecureCode()
	if err != nil {
		slog.Error("verify-email: failed to generate auth code", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "expired", "", params, "Verification succeeded but login failed. Please log in manually.")
		return
	}

	code := authcode.AuthCode{
		Code:                authCodeStr,
		UserID:              userID,
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(config.Get().AuthAuthorizationCodeExpiration),
		Used:                false,
	}

	if err = authcode.CreateAuthCode(code); err != nil {
		slog.Error("verify-email: failed to create auth code", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "expired", "", params, "Verification succeeded but login failed. Please log in manually.")
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", params.RedirectURI, code.Code, params.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleResendVerification handles POST /oauth2/resend-verification
func HandleResendVerification(w http.ResponseWriter, r *http.Request) {
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
	}

	usr, err := user.UserByUsername(username)
	if err != nil {
		// Don't leak whether the user exists — show success anyway.
		// Prevent timing-based user enumeration.
		utils.RandomDelay()
		RenderVerifyEmail(w, r, "sent", username, params, "")
		return
	}

	if usr.IsEmailVerified {
		RenderVerifyEmail(w, r, "sent", username, params, "Your email is already verified. You can now log in.")
		return
	}

	if usr.Email == "" {
		RenderVerifyEmail(w, r, "sent", username, params, "")
		return
	}

	rawToken, tokenHash, err := GenerateToken()
	if err != nil {
		slog.Error("resend-verification: failed to generate token", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "sent", username, params, "Something went wrong. Please try again.")
		return
	}

	expiresAt := time.Now().Add(config.Get().EmailVerificationExpiration)
	if err := user.SetEmailVerificationToken(usr.ID, tokenHash, expiresAt); err != nil {
		slog.Error("resend-verification: failed to store token", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		RenderVerifyEmail(w, r, "sent", username, params, "Something went wrong. Please try again.")
		return
	}

	verifyURL := BuildVerifyURL(rawToken, params)
	if err := mfa.SendVerificationEmail(usr.Email, verifyURL); err != nil {
		slog.Error("resend-verification: failed to send email", "request_id", middleware.GetRequestID(r.Context()), "error", err)
	}

	RenderVerifyEmail(w, r, "sent", username, params, "")
}
