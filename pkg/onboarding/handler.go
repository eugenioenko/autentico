package onboarding

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

// HandleOnboard manages the first-time setup of the admin account.
// This endpoint only works if the system is not yet onboarded.
// @Summary Initial admin setup
// @Description Renders the onboarding page (GET) or creates the initial administrator (POST).
// @Tags onboarding
// @Accept x-www-form-urlencoded
// @Produce html
// @Param username formData string false "Admin username"
// @Param password formData string false "Admin password"
// @Param confirm_password formData string false "Confirm password"
// @Param email formData string false "Admin email"
// @Param redirect_uri formData string false "Redirect URI"
// @Param state formData string false "OAuth2 state"
// @Success 200 {string} string "Onboarding form (GET)"
// @Success 302 {string} string "Redirect to admin UI after success (POST)"
// @Router /oauth2/onboard [get]
// @Router /oauth2/onboard [post]
func HandleOnboard(w http.ResponseWriter, r *http.Request) {
	// Only allow onboarding if BOTH the flag is false AND the users table is empty.
	count, _ := user.CountUsers()
	if appsettings.IsOnboarded() || count > 0 {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleOnboardGet(w, r)
	case http.MethodPost:
		handleOnboardPost(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

func handleOnboardGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	renderOnboard(w, r, onboardParams{
		State:               q.Get("state"),
		RedirectURI:         q.Get("redirect_uri"),
		ClientID:            q.Get("client_id"),
		Scope:               q.Get("scope"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}, "")
}

func handleOnboardPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	params := onboardParams{
		State:               r.FormValue("state"),
		RedirectURI:         r.FormValue("redirect_uri"),
		ClientID:            r.FormValue("client_id"),
		Scope:               r.FormValue("scope"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	if !utils.IsValidRedirectURI(params.RedirectURI) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	email := r.FormValue("email")

	if password != confirmPassword {
		renderOnboard(w, r, params, "Passwords do not match")
		return
	}

	req := user.UserCreateRequest{
		Username: username,
		Password: password,
		Email:    email,
	}
	if err := user.ValidateUserCreateRequest(req); err != nil {
		renderOnboard(w, r, params, err.Error())
		return
	}

	// Double check user count just to be safe
	count, countErr := user.CountUsers()
	if countErr != nil || count > 0 {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "onboarding_already_completed", "Setup already finished")
		return
	}

	usr, err := user.CreateUser(username, password, email)
	if err != nil {
		renderOnboard(w, r, params, "Could not create administrator account.")
		return
	}

	// Grant admin role and mark as onboarded.
	_ = user.UpdateUser(usr.ID, usr.Email, "admin")
	_ = appsettings.SetSetting("onboarded", "true")
	_ = appsettings.LoadIntoConfig()

	// Create IdP session if SSO is enabled
	if config.Get().AuthSsoSessionIdleTimeout > 0 {
		sessionID, err := authcode.GenerateSecureCode()
		if err == nil {
			session := idpsession.IdpSession{
				ID:        sessionID,
				UserID:    usr.ID,
				UserAgent: r.UserAgent(),
				IPAddress: utils.GetClientIP(r),
			}
			if idpsession.CreateIdpSession(session) == nil {
				idpsession.SetCookie(w, sessionID)
			}
		}
	}

	authCode, err := authcode.GenerateSecureCode()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate authorization code")
		return
	}

	code := authcode.AuthCode{
		Code:                authCode,
		UserID:              usr.ID,
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create authorization code")
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", params.RedirectURI, code.Code, params.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

type onboardParams struct {
	State               string
	RedirectURI         string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func renderOnboard(w http.ResponseWriter, r *http.Request, params onboardParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("onboard")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"State":               params.State,
		"RedirectURI":         params.RedirectURI,
		"ClientID":            params.ClientID,
		"Scope":               params.Scope,
		"Nonce":               params.Nonce,
		"CodeChallenge":       params.CodeChallenge,
		"CodeChallengeMethod": params.CodeChallengeMethod,
		"Error":               errMsg,
		"UsernameIsEmail":     cfg.ValidationUsernameIsEmail,
		"EmailRequired":       cfg.ValidationEmailRequired && !cfg.ValidationUsernameIsEmail,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeCssResolved":    template.CSS(cfg.ThemeCssResolved),
	}

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
