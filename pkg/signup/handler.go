package signup

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/mfa"
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
	RenderSignup(w, r, SignupParams{
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
	// In passkey_only mode the form is never POSTed — JS handles everything via
	// /passkey/register/begin and /passkey/register/finish. Re-render the form.
	if config.Get().AuthMode == "passkey_only" {
		handleSignupGet(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	params := SignupParams{
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
	if config.Get().ProfileFieldEmail == "is_username" && email == "" {
		email = username
	}

	if password != confirmPassword {
		redirectSignupError(w, r, params, "Passwords do not match")
		return
	}

	req := user.UserCreateRequest{
		Username: username,
		Password: password,
		Email:    email,
	}
	if err := user.ValidateUserCreateRequest(req); err != nil {
		redirectSignupError(w, r, params, err.Error())
		return
	}

	// Validate required profile fields
	cfg := config.Get()
	profileFields := map[string]string{
		"given_name":          r.FormValue("given_name"),
		"family_name":         r.FormValue("family_name"),
		"phone_number":        r.FormValue("phone_number"),
		"picture":             r.FormValue("picture"),
		"locale":              r.FormValue("locale"),
		"address_street":      r.FormValue("address_street"),
		"address_locality":    r.FormValue("address_locality"),
		"address_region":      r.FormValue("address_region"),
		"address_postal_code": r.FormValue("address_postal_code"),
		"address_country":     r.FormValue("address_country"),
	}
	fieldVisibility := map[string]string{
		"given_name":   cfg.ProfileFieldGivenName,
		"family_name":  cfg.ProfileFieldFamilyName,
		"phone_number": cfg.ProfileFieldPhone,
		"picture":      cfg.ProfileFieldPicture,
		"locale":       cfg.ProfileFieldLocale,
		"address_street": cfg.ProfileFieldAddress,
		"address_locality": cfg.ProfileFieldAddress,
		"address_region": cfg.ProfileFieldAddress,
		"address_postal_code": cfg.ProfileFieldAddress,
		"address_country": cfg.ProfileFieldAddress,
	}
	for field, visibility := range fieldVisibility {
		if visibility == "required" && profileFields[field] == "" {
			redirectSignupError(w, r, params, "Please fill in all required fields")
			return
		}
	}

	usr, err := user.CreateUser(username, password, email)
	if err != nil {
		redirectSignupError(w, r, params, "Could not create account. Username may already be taken.")
		return
	}
	audit.Log(audit.EventUserCreated, nil, audit.TargetUser, usr.ID, audit.Detail("source", "signup", "username", username), utils.GetClientIP(r))

	// Save optional/required profile fields
	profileUpdate := user.UserUpdateRequest{
		GivenName:         profileFields["given_name"],
		FamilyName:        profileFields["family_name"],
		PhoneNumber:       profileFields["phone_number"],
		Picture:           profileFields["picture"],
		Locale:            profileFields["locale"],
		AddressStreet:     profileFields["address_street"],
		AddressLocality:   profileFields["address_locality"],
		AddressRegion:     profileFields["address_region"],
		AddressPostalCode: profileFields["address_postal_code"],
		AddressCountry:    profileFields["address_country"],
	}
	_ = user.UpdateUser(usr.ID, profileUpdate)

	// Email verification gate — non-admin users with an email must verify before logging in
	if config.Get().RequireEmailVerification && usr.Email != "" && usr.Role != "admin" {
		rawToken, tokenHash, err := emailverification.GenerateToken()
		if err == nil {
			expiresAt := time.Now().Add(config.Get().EmailVerificationExpiration)
			_ = user.SetEmailVerificationToken(usr.ID, tokenHash, expiresAt)
			verifyURL := emailverification.BuildVerifyURL(rawToken, emailverification.OAuthParams{
				RedirectURI:         params.RedirectURI,
				State:               params.State,
				ClientID:            params.ClientID,
				Scope:               params.Scope,
				Nonce:               params.Nonce,
				CodeChallenge:       params.CodeChallenge,
				CodeChallengeMethod: params.CodeChallengeMethod,
			})
			_ = mfa.SendVerificationEmail(usr.Email, verifyURL)
		}
		emailverification.RenderVerifyEmail(w, r, "sent", usr.Username, emailverification.OAuthParams{
			RedirectURI:         params.RedirectURI,
			State:               params.State,
			ClientID:            params.ClientID,
			Scope:               params.Scope,
			Nonce:               params.Nonce,
			CodeChallenge:       params.CodeChallenge,
			CodeChallengeMethod: params.CodeChallengeMethod,
		}, "")
		return
	}

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
		slog.Error("signup: failed to generate auth code", "error", err)
		redirectSignupError(w, r, params, "Something went wrong. Please try again.")
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
		slog.Error("signup: failed to create auth code", "error", err)
		redirectSignupError(w, r, params, "Something went wrong. Please try again.")
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", params.RedirectURI, code.Code, params.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

type SignupParams struct {
	State               string
	RedirectURI         string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func RenderSignup(w http.ResponseWriter, r *http.Request, params SignupParams, errMsg string) {
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
		"AuthMode":            cfg.AuthMode,
		"ProfileFieldEmail":        cfg.ProfileFieldEmail,
		"ShowOptionalFields":       cfg.SignupShowOptionalFields,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeCssResolved":    template.CSS(cfg.ThemeCssResolved),
		// Profile field visibility
		"ProfileFieldGivenName":  cfg.ProfileFieldGivenName,
		"ProfileFieldFamilyName": cfg.ProfileFieldFamilyName,
		"ProfileFieldPhone":      cfg.ProfileFieldPhone,
		"ProfileFieldPicture":    cfg.ProfileFieldPicture,
		"ProfileFieldLocale":     cfg.ProfileFieldLocale,
		"ProfileFieldAddress":    cfg.ProfileFieldAddress,
	}

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// redirectSignupError redirects back to /oauth2/authorize?prompt=create with the error
// and all OAuth params preserved, so the user stays in the authorize flow.
func redirectSignupError(w http.ResponseWriter, r *http.Request, params SignupParams, errMsg string) {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("prompt", "create")
	q.Set("error", errMsg)
	q.Set("client_id", params.ClientID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("scope", params.Scope)
	q.Set("state", params.State)
	q.Set("nonce", params.Nonce)
	q.Set("code_challenge", params.CodeChallenge)
	q.Set("code_challenge_method", params.CodeChallengeMethod)
	http.Redirect(w, r, "/oauth2/authorize?"+q.Encode(), http.StatusFound)
}
