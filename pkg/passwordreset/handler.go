package passwordreset

import (
	"database/sql"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

// oauthParams holds the OAuth2 authorization request parameters needed to
// return the user to the login page after password reset.
type oauthParams struct {
	RedirectURI         string
	State               string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func paramsFromRequest(r *http.Request, getter func(string) string) oauthParams {
	return oauthParams{
		RedirectURI:         getter("redirect_uri"),
		State:               getter("state"),
		ClientID:            getter("client_id"),
		Scope:               getter("scope"),
		Nonce:               getter("nonce"),
		CodeChallenge:       getter("code_challenge"),
		CodeChallengeMethod: getter("code_challenge_method"),
	}
}

func renderForgotPassword(w http.ResponseWriter, r *http.Request, mode string, params oauthParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("forgot_password")
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
		"Error":               errMsg,
		"ProfileFieldEmail":   cfg.ProfileFieldEmail,
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeCssResolved":    template.CSS(cfg.ThemeCssResolved),
		csrf.TemplateTag:      csrf.TemplateField(r),
	}
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

func renderResetPassword(w http.ResponseWriter, r *http.Request, mode, token string, params oauthParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("reset_password")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Mode":                mode,
		"Token":               token,
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

// HandleForgotPassword handles GET and POST for /oauth2/forgot-password.
// GET renders the form. POST looks up the user, creates a reset token, and sends the email.
func HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		params := paramsFromRequest(r, r.URL.Query().Get)
		renderForgotPassword(w, r, "form", params, "")
		return
	}

	// POST
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	params := paramsFromRequest(r, r.FormValue)
	identifier := r.FormValue("identifier")

	if identifier == "" {
		renderForgotPassword(w, r, "form", params, "Please enter your username or email.")
		return
	}

	// Always show success to prevent user enumeration.
	// Silently skip if we can't find the user or they have no email.
	cfg := config.Get()
	reqID := middleware.GetRequestID(r.Context())

	var usr *user.User
	var err error

	// Try username first, then email (verified only)
	usr, err = user.UserByUsername(identifier)
	if err != nil {
		usr, err = user.UserByEmail(identifier)
	}

	if err != nil || usr == nil || usr.Email == "" || !usr.IsEmailVerified {
		// Don't leak whether the user exists
		renderForgotPassword(w, r, "sent", params, "")
		return
	}

	// Invalidate any previous unused reset tokens for this user
	invalidatePreviousTokens(usr.ID)

	rawToken, tokenHash, err := generateToken()
	if err != nil {
		slog.Error("forgot-password: failed to generate token", "request_id", reqID, "error", err)
		renderForgotPassword(w, r, "sent", params, "")
		return
	}

	expiresAt := time.Now().Add(cfg.PasswordResetExpiration)
	if err := createResetToken(usr.ID, tokenHash, expiresAt); err != nil {
		slog.Error("forgot-password: failed to store token", "request_id", reqID, "error", err)
		renderForgotPassword(w, r, "sent", params, "")
		return
	}

	resetURL := buildResetURL(rawToken, params)
	if err := mfa.SendPasswordResetEmail(usr.Email, resetURL); err != nil {
		slog.Error("forgot-password: failed to send email", "request_id", reqID, "error", err)
	}

	renderForgotPassword(w, r, "sent", params, "")
}

// HandleResetPassword handles GET and POST for /oauth2/reset-password.
// GET renders the new-password form. POST validates the token and updates the password.
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		params := paramsFromRequest(r, r.URL.Query().Get)
		rawToken := r.URL.Query().Get("token")
		if rawToken == "" {
			renderResetPassword(w, r, "expired", "", params, "Invalid or missing reset link.")
			return
		}

		// Validate the token is still valid before showing the form
		tokenHash := utils.HashSHA256(rawToken)
		_, expiresAt, usedAt, err := getResetTokenInfo(tokenHash)
		if err != nil || usedAt != nil || time.Now().After(expiresAt) {
			renderResetPassword(w, r, "expired", "", params, "This password reset link has expired or has already been used.")
			return
		}

		renderResetPassword(w, r, "form", rawToken, params, "")
		return
	}

	// POST
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	params := paramsFromRequest(r, r.FormValue)
	rawToken := r.FormValue("token")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if rawToken == "" {
		renderResetPassword(w, r, "expired", "", params, "Invalid or missing reset token.")
		return
	}

	reqID := middleware.GetRequestID(r.Context())

	// Validate passwords match
	if password != confirmPassword {
		renderResetPassword(w, r, "form", rawToken, params, "Passwords do not match.")
		return
	}

	// Validate password length
	cfg := config.Get()
	if len(password) < cfg.ValidationMinPasswordLength {
		renderResetPassword(w, r, "form", rawToken, params,
			fmt.Sprintf("Password must be at least %d characters.", cfg.ValidationMinPasswordLength))
		return
	}
	if len(password) > cfg.ValidationMaxPasswordLength {
		renderResetPassword(w, r, "form", rawToken, params, "Password is too long.")
		return
	}

	// Look up and validate the token
	tokenHash := utils.HashSHA256(rawToken)
	userID, expiresAt, usedAt, err := getResetTokenInfo(tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			renderResetPassword(w, r, "expired", "", params, "This password reset link is invalid or has already been used.")
			return
		}
		slog.Error("reset-password: failed to look up token", "request_id", reqID, "error", err)
		renderResetPassword(w, r, "expired", "", params, "Something went wrong. Please request a new reset link.")
		return
	}

	if usedAt != nil {
		renderResetPassword(w, r, "expired", "", params, "This password reset link has already been used.")
		return
	}

	if time.Now().After(expiresAt) {
		renderResetPassword(w, r, "expired", "", params, "This password reset link has expired.")
		return
	}

	// Update the user's password
	if err := user.UpdateUser(userID, user.UserUpdateRequest{Password: password}); err != nil {
		slog.Error("reset-password: failed to update password", "request_id", reqID, "error", err)
		renderResetPassword(w, r, "form", rawToken, params, "Failed to update password. Please try again.")
		return
	}

	// Mark token as used
	markTokenUsed(tokenHash)

	// Invalidate all sessions for this user (security: password was compromised)
	deactivateUserSessions(userID)
	_ = idpsession.DeactivateAllForUser(userID)

	renderResetPassword(w, r, "success", "", params, "")
}

// buildResetURL constructs the full reset link to embed in the email.
func buildResetURL(rawToken string, p oauthParams) string {
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
	return bs.AppURL + bs.AppOAuthPath + "/reset-password?" + q.Encode()
}
