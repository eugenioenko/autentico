package authorize

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"

	"github.com/gorilla/csrf"
)

// HandleAuthorize godoc
// @Summary Authorize a client
// @Description Handles the authorization request and displays the login page
// @Tags authorize
// @Accept json
// @Produce html
// @Param response_type query string true "Response type"
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param scope query string false "Scope"
// @Param state query string true "State"
// @Success 200 {string} string "HTML login page"
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/authorize [get]
func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	request := AuthorizeRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),                 // TODO
		CodeChallenge:       q.Get("code_challenge"),        // TODO
		CodeChallengeMethod: q.Get("code_challenge_method"), // TODO
	}

	err := ValidateAuthorizeRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_request", err.Error())
		return
	}

	// Validate redirect_uri format
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	// If client_id is provided, validate against registered clients
	var registeredClient *client.Client
	if request.ClientID != "" {
		registeredClient, err = client.ClientByClientID(request.ClientID)
		if err != nil {
			// Client not found - for backward compatibility, allow if no clients registered
			// This maintains existing behavior for deployments without registered clients
		} else {
			// Client found - validate redirect_uri and response_type
			if !registeredClient.IsActive {
				utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client", "Client is inactive")
				return
			}

			if !client.IsValidRedirectURI(registeredClient, request.RedirectURI) {
				utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Redirect URI not allowed for this client")
				return
			}

			if !client.IsResponseTypeAllowed(registeredClient, request.ResponseType) {
				utils.WriteErrorResponse(w, http.StatusBadRequest, "unsupported_response_type", "Response type not allowed for this client")
				return
			}
		}
	}

	// Check for valid IdP session (auto-login)
	cfg := config.Get()
	if cfg.AuthSsoSessionIdleTimeout > 0 {
		sessionID := idpsession.ReadCookie(r)
		if sessionID != "" {
			session, err := idpsession.IdpSessionByID(sessionID)
			if err == nil && time.Since(session.LastActivityAt) < cfg.AuthSsoSessionIdleTimeout {
				// Valid IdP session — auto-login
				_ = idpsession.UpdateLastActivity(session.ID)

				code, err := authcode.GenerateSecureCode()
				if err == nil {
					ac := authcode.AuthCode{
						Code:        code,
						UserID:      session.UserID,
						ClientID:    request.ClientID,
						RedirectURI: request.RedirectURI,
						Scope:       "read write",
						ExpiresAt:   time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
						Used:        false,
					}
					if authcode.CreateAuthCode(ac) == nil {
						redirectURL := fmt.Sprintf("%s?code=%s&state=%s", request.RedirectURI, ac.Code, request.State)
						http.Redirect(w, r, redirectURL, http.StatusFound)
						return
					}
				}
			}
		}
	}

	tmpl, err := template.New("login").Parse(view.LoginTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"State":          request.State,
		"Redirect":       request.RedirectURI,
		"ClientID":       request.ClientID,
		csrf.TemplateTag: csrf.TemplateField(r),
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
