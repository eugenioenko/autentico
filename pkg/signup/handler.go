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
	"github.com/eugenioenko/autentico/pkg/authrequest"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/middleware"
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
// HandleSignupPage renders the signup form (GET). Reads auth_request_id from query.
func HandleSignupPage(w http.ResponseWriter, r *http.Request) {
	if !config.Get().AuthAllowSelfSignup {
		http.NotFound(w, r)
		return
	}

	authReqID := r.URL.Query().Get("auth_request_id")
	if authReqID == "" {
		renderSignupError(w, "Missing authorization request. Please return to the application and try again.")
		return
	}

	authReq, err := authrequest.GetByID(authReqID)
	if err != nil {
		slog.Warn("signup_page: invalid or expired auth request", "auth_request_id", authReqID, "error", err)
		renderSignupError(w, "Authorization request expired. Please return to the application and try again.")
		return
	}

	errMsg := r.URL.Query().Get("error")
	RenderSignup(w, r, authReq, errMsg)
}

func HandleSignup(w http.ResponseWriter, r *http.Request) {
	if !config.Get().AuthAllowSelfSignup {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodPost:
		handleSignupPost(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

func handleSignupPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	// Look up stored authorize request — all OAuth parameters come from the
	// server-side record, not from the POST body (issues #184, #186).
	authReqID := r.FormValue("auth_request_id")
	if authReqID == "" {
		renderSignupError(w, "Missing authorization request. Please return to the application and try again.")
		return
	}

	authReq, err := authrequest.GetByID(authReqID)
	if err != nil {
		slog.Warn("signup: invalid or expired auth request", "request_id", middleware.GetRequestID(r.Context()), "auth_request_id", authReqID, "error", err)
		renderSignupError(w, "Authorization request expired. Please return to the application and try again.")
		return
	}

	// In passkey_only mode the form is never POSTed — JS handles everything via
	// /passkey/register/begin and /passkey/register/finish. Re-render the form.
	if config.Get().AuthMode == "passkey_only" {
		RenderSignup(w, r, authReq, "")
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
		redirectSignupErrorWithID(w, r, authReqID, "Passwords do not match")
		return
	}

	req := user.UserCreateRequest{
		Username: username,
		Password: password,
		Email:    email,
	}
	if err := user.ValidateUserCreateRequest(req); err != nil {
		redirectSignupErrorWithID(w, r, authReqID, err.Error())
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
			redirectSignupErrorWithID(w, r, authReqID, "Please fill in all required fields")
			return
		}
	}

	usr, err := user.CreateUser(username, password, email)
	if err != nil {
		redirectSignupErrorWithID(w, r, authReqID, "Could not create account. Username may already be taken.")
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
				RedirectURI:         authReq.RedirectURI,
				State:               authReq.State,
				ClientID:            authReq.ClientID,
				Scope:               authReq.Scope,
				Nonce:               authReq.Nonce,
				CodeChallenge:       authReq.CodeChallenge,
				CodeChallengeMethod: authReq.CodeChallengeMethod,
			})
			_ = mfa.SendVerificationEmail(usr.Email, verifyURL)
		}
		emailverification.RenderVerifyEmail(w, r, "sent", usr.Username, emailverification.OAuthParams{
			RedirectURI:         authReq.RedirectURI,
			State:               authReq.State,
			ClientID:            authReq.ClientID,
			Scope:               authReq.Scope,
			Nonce:               authReq.Nonce,
			CodeChallenge:       authReq.CodeChallenge,
			CodeChallengeMethod: authReq.CodeChallengeMethod,
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
		redirectSignupErrorWithID(w, r, authReqID, "Something went wrong. Please try again.")
		return
	}

	code := authcode.AuthCode{
		Code:                authCode,
		UserID:              usr.ID,
		ClientID:            authReq.ClientID,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		Nonce:               authReq.Nonce,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(config.Get().AuthAuthorizationCodeExpiration),
		Used:                false,
	}

	if err = authcode.CreateAuthCode(code); err != nil {
		slog.Error("signup: failed to create auth code", "error", err)
		redirectSignupErrorWithID(w, r, authReqID, "Something went wrong. Please try again.")
		return
	}

	// Consume the authorize request to prevent reuse
	_ = authrequest.Delete(authReqID)

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectURI, code.Code, authReq.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// RenderSignup renders the signup form using stored authorize request parameters.
func RenderSignup(w http.ResponseWriter, r *http.Request, authReq *authrequest.AuthorizeRequest, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("signup")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"AuthRequestID":       authReq.ID,
		"ClientID":            authReq.ClientID,
		"Error":               errMsg,
		"AuthMode":            cfg.AuthMode,
		"ProfileFieldEmail":        cfg.ProfileFieldEmail,
		"ShowOptionalFields":       cfg.SignupShowOptionalFields,
		csrf.TemplateTag:      csrf.TemplateField(r),
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		"ThemeCssResolved":    template.CSS(cfg.ThemeCssResolved),
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

// redirectSignupErrorWithID redirects back to the signup page with an error message,
// preserving the auth request ID so the form is re-rendered with stored params.
func redirectSignupErrorWithID(w http.ResponseWriter, r *http.Request, authReqID string, errMsg string) {
	signupURL := config.GetBootstrap().AppOAuthPath + "/signup?auth_request_id=" + authReqID + "&error=" + url.QueryEscape(errMsg)
	http.Redirect(w, r, signupURL, http.StatusFound)
}

// renderSignupError renders a branded error page for authorization request failures.
func renderSignupError(w http.ResponseWriter, errorMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("error")
	if err != nil {
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
	_ = tmpl.ExecuteTemplate(w, "layout", data)
}
