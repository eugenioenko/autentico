package onboarding

import (
	"html/template"
	"net/http"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

// HandleOnboardDirect handles GET/POST /onboard — a direct onboarding URL that requires no
// OIDC state. After setup completes the user is redirected to /admin/ where the IdP session
// created here allows silent SSO login without re-entering credentials.
// CSRF-protected form — not included in public API docs.
//
// Methods: GET, POST
// Route: /onboard
// Accept: x-www-form-urlencoded
// Produce: html
// Param username formData string false "Admin username"
// Param password formData string false "Admin password"
// Param confirm_password formData string false "Confirm password"
// Param email formData string false "Admin email"
// Success 200 "Onboarding form (GET)"
// Success 302 "Redirect to /admin/ after success (POST)"
func HandleOnboardDirect(w http.ResponseWriter, r *http.Request) {
	count, _ := user.CountUsers()
	if appsettings.IsOnboarded() || count > 0 {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		renderOnboard(w, r, onboardParams{FormAction: "/onboard"}, "")
	case http.MethodPost:
		handleOnboardDirectPost(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}

func handleOnboardDirectPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	params := onboardParams{FormAction: "/onboard"}
	username := r.FormValue("username")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	email := r.FormValue("email")

	if password != confirmPassword {
		renderOnboard(w, r, params, "Passwords do not match")
		return
	}

	req := user.UserCreateRequest{Username: username, Password: password, Email: email}
	if err := user.ValidateUserCreateRequest(req); err != nil {
		renderOnboard(w, r, params, err.Error())
		return
	}

	count, countErr := user.CountUsers()
	if countErr != nil || count > 0 {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}

	usr, err := user.CreateUser(username, password, email)
	if err != nil {
		renderOnboard(w, r, params, "Could not create administrator account.")
		return
	}

	_ = user.UpdateUser(usr.ID, user.UserUpdateRequest{Email: usr.Email, Role: "admin"})
	_ = appsettings.SetSetting("onboarded", "true")
	_ = appsettings.LoadIntoConfig()

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

	http.Redirect(w, r, "/admin/", http.StatusFound)
}

type onboardParams struct {
	FormAction string
}

func renderOnboard(w http.ResponseWriter, r *http.Request, params onboardParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("onboard")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"FormAction":        params.FormAction,
		"Error":             errMsg,
		"ProfileFieldEmail": cfg.ProfileFieldEmail,
		csrf.TemplateTag:    csrf.TemplateField(r),
		"ThemeTitle":        cfg.Theme.Title,
		"ThemeLogoUrl":      cfg.Theme.LogoUrl,
		"ThemeCssResolved":  template.CSS(cfg.ThemeCssResolved),
	}

	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
