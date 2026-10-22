package signup

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/email"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

// HandleSignup handles user registration requests.
// CSRF-protected form — not included in public API docs.
//
// Method: POST
// Route: /oauth2/signup
// Accept: x-www-form-urlencoded
// Produce: html
// Param username formData string false "Desired username"
// Param password formData string false "Password"
// Param confirm_password formData string false "Confirm password"
// Param email formData string false "Email address"
// Param redirect_uri formData string false "Redirect URI"
// Param state formData string false "OAuth2 state"
// Success 302 "Redirect back to client with code"
func HandleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		view.RenderError(w, r, http.StatusMethodNotAllowed, "This page can only be accessed through the signup flow.")
		return
	}

	handleSignupPost(w, r)
}

// handleSignupPost registers an account under current client policy, then requires verification, MFA and consent as configured.
func handleSignupPost(w http.ResponseWriter, r *http.Request) {
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
		AuthorizeSig:        r.FormValue("authorize_sig"),
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
	}, params.AuthorizeSig) {
		slog.Warn("signup: authorize parameter signature mismatch", "client_id", params.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Authorization request parameters have been tampered with")
		return
	}

	if !utils.IsValidRedirectURI(params.RedirectURI) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	// RFC 6749 §4.1.1 / §10.6: validate the current client and callback before creating an account.
	registeredClient, err := client.ValidateAuthorization(authzsig.FromValues(r.Form))
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// RFC 6749 §2: apply the current registration's local signup policy before
	// account creation. Explicit client true/false overrides the global default.
	cfg := config.GetForClient(registeredClient.ToOverrides())
	if !cfg.AuthAllowSelfSignup {
		view.RenderError(w, r, http.StatusMethodNotAllowed, "Self-registration is not enabled for this client.")
		return
	}

	// In passkey_only mode the form is never POSTed — JS handles everything via
	// /passkey/register/begin and /passkey/register/finish. Re-render the form.
	if cfg.AuthMode == "passkey_only" {
		RenderSignup(w, r, params, "")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	emailAddr := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if config.Get().ProfileFieldEmail == "is_username" && emailAddr == "" {
		username = strings.ToLower(username)
		emailAddr = username
	}

	// Local verification policy requires an address even if the profile field is optional.
	if config.Get().RequireEmailVerification && emailAddr == "" {
		redirectSignupError(w, r, params, "Email is required for verification")
		return
	}

	if password != confirmPassword {
		redirectSignupError(w, r, params, "Passwords do not match")
		return
	}

	req := user.UserCreateRequest{
		Username: username,
		Password: password,
		Email:    emailAddr,
	}
	if err := user.ValidateUserCreateRequest(req); err != nil {
		redirectSignupError(w, r, params, err.Error())
		return
	}

	// Validate required profile fields
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
		"given_name":          cfg.ProfileFieldGivenName,
		"family_name":         cfg.ProfileFieldFamilyName,
		"phone_number":        cfg.ProfileFieldPhone,
		"picture":             cfg.ProfileFieldPicture,
		"locale":              cfg.ProfileFieldLocale,
		"address_street":      cfg.ProfileFieldAddress,
		"address_locality":    cfg.ProfileFieldAddress,
		"address_region":      cfg.ProfileFieldAddress,
		"address_postal_code": cfg.ProfileFieldAddress,
		"address_country":     cfg.ProfileFieldAddress,
	}
	for field, visibility := range fieldVisibility {
		if visibility == "required" && profileFields[field] == "" {
			redirectSignupError(w, r, params, "Please fill in all required fields")
			return
		}
	}

	// Validate profile fields (e.g. URL scheme checks) before creating the user
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
	if err := user.ValidateUserUpdateRequest(profileUpdate); err != nil {
		redirectSignupError(w, r, params, err.Error())
		return
	}

	usr, err := user.CreateUser(username, password, emailAddr)
	if err != nil {
		redirectSignupError(w, r, params, "Could not create account. Username may already be taken.")
		return
	}
	audit.Log(audit.EventUserCreated, nil, audit.TargetUser, usr.ID, audit.Detail("source", "signup", "username", username), utils.GetClientIP(r))

	// Save profile fields
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
				AuthorizeSig:        params.AuthorizeSig,
			})
			_ = email.SendVerificationEmail(usr.Email, verifyURL)
		}
		emailverification.RenderVerifyEmail(w, r, "sent", usr.Username, emailverification.OAuthParams{
			RedirectURI:         params.RedirectURI,
			State:               params.State,
			ClientID:            params.ClientID,
			Scope:               params.Scope,
			Nonce:               params.Nonce,
			CodeChallenge:       params.CodeChallenge,
			CodeChallengeMethod: params.CodeChallengeMethod,
			AuthorizeSig:        params.AuthorizeSig,
		}, "")
		return
	}

	// OIDC Core §3.1.2.3–4: account creation alone does not establish MFA.
	nextURL, err := mfa.FinishLogin(w, r, usr.ID, mfa.LoginState{
		RedirectURI:         params.RedirectURI,
		State:               params.State,
		ClientID:            params.ClientID,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
	}, mfa.PrimarySignup)
	if err != nil {
		slog.Error("signup: failed to complete authentication", "error", err)
		redirectSignupError(w, r, params, "Something went wrong. Please try again.")
		return
	}
	// RFC 6749 §4.1.2: follow the validated next authentication step.
	http.Redirect(w, r, nextURL, http.StatusFound)
}

type SignupParams struct {
	State               string
	RedirectURI         string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthorizeSig        string
}

func RenderSignup(w http.ResponseWriter, r *http.Request, params SignupParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("signup")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"State":                    params.State,
		"RedirectURI":              params.RedirectURI,
		"ClientID":                 params.ClientID,
		"Scope":                    params.Scope,
		"Nonce":                    params.Nonce,
		"CodeChallenge":            params.CodeChallenge,
		"CodeChallengeMethod":      params.CodeChallengeMethod,
		"AuthorizeSig":             params.AuthorizeSig,
		"Error":                    errMsg,
		"AuthMode":                 cfg.AuthMode,
		"ProfileFieldEmail":        cfg.ProfileFieldEmail,
		"RequireEmailVerification": cfg.RequireEmailVerification,
		"ShowOptionalFields":       cfg.SignupShowOptionalFields,
		csrf.TemplateTag:           csrf.TemplateField(r),
		"ThemeTitle":               cfg.Theme.Title,
		"ThemeLogoUrl":             cfg.Theme.LogoUrl,
		"ThemeTagline":             cfg.Theme.Tagline,
		// Profile field visibility
		"ProfileFieldGivenName":  cfg.ProfileFieldGivenName,
		"ProfileFieldFamilyName": cfg.ProfileFieldFamilyName,
		"ProfileFieldPhone":      cfg.ProfileFieldPhone,
		"ProfileFieldPicture":    cfg.ProfileFieldPicture,
		"ProfileFieldLocale":     cfg.ProfileFieldLocale,
		"ProfileFieldAddress":    cfg.ProfileFieldAddress,
	}
	view.InjectNonce(r, data)

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
	http.Redirect(w, r, config.GetBootstrap().AppOAuthPath+"/authorize?"+q.Encode(), http.StatusFound)
}
