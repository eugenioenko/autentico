package signup

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

// HandleSignup handles user registration requests.
// @Summary User signup
// @Description Renders the signup page (GET) or processes a new user registration (POST).
// @Tags signup
// @Accept x-www-form-urlencoded
// @Produce html
// @Param username formData string false "Desired username"
// @Param password formData string false "Password"
// @Param confirm_password formData string false "Confirm password"
// @Param email formData string false "Email address"
// @Param redirect_uri formData string false "Redirect URI"
// @Param state formData string false "OAuth2 state"
// @Success 200 {string} string "Signup form (GET)"
// @Success 302 {string} string "Redirect back to client with code (POST)"
// @Router /oauth2/signup [get]
// @Router /oauth2/signup [post]
func HandleSignup(w http.ResponseWriter, r *http.Request) {
	if !config.Get().AuthAllowSelfSignup {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleSignupGet(w, r)
	case http.MethodPost:
		handleSignupPost(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

func handleSignupGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	renderSignup(w, r, signupParams{
		State:               q.Get("state"),
		RedirectURI:         q.Get("redirect_uri"),
		ClientID:            q.Get("client_id"),
		Scope:               q.Get("scope"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}, "")
}

func handleSignupPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	params := signupParams{
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
		renderSignup(w, r, params, "Passwords do not match")
		return
	}

	req := user.UserCreateRequest{
		Username: username,
		Password: password,
		Email:    email,
	}
	if err := user.ValidateUserCreateRequest(req); err != nil {
		renderSignup(w, r, params, err.Error())
		return
	}

	usr, err := user.CreateUser(username, password, email)
	if err != nil {
		renderSignup(w, r, params, "Could not create account. Username may already be taken.")
		return
	}

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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code generation. %v", err))
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code insert. %v", err))
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", params.RedirectURI, code.Code, params.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

type signupParams struct {
	State               string
	RedirectURI         string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func renderSignup(w http.ResponseWriter, r *http.Request, params signupParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("signup")
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
