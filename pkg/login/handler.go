package login

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleLoginUser godoc
// @Summary Log in a user
// @Description Authenticates a user and generates an authorization code
// @Tags auth
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param username formData string true "Username"
// @Param password formData string true "Password"
// @Param redirect formData string true "Redirect URI"
// @Param state formData string true "State"
// @Success 302 {string} string "Redirect to the provided URI with code and state"
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/login [post]
func HandleLoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Only POST method is allowed")
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	request := LoginRequest{
		Username:            r.FormValue("username"),
		Password:            r.FormValue("password"),
		Redirect:            r.FormValue("redirect"),
		State:               r.FormValue("state"),
		ClientID:            r.FormValue("client_id"),
		Scope:               r.FormValue("scope"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	err = ValidateLoginRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("user credentials error. %v", err))
		return
	}

	// Validate redirect_uri
	if !utils.IsValidRedirectURI(request.Redirect) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	usr, err := user.AuthenticateUser(request.Username, request.Password)
	if err != nil {
		if errors.Is(err, user.ErrAccountLocked) {
			utils.WriteErrorResponse(w, http.StatusForbidden, "account_locked", err.Error())
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("login failed. %v", err))
		return
	}

	// Create IdP session if authSsoSessionIdleTimeout is enabled
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
		ClientID:            request.ClientID,
		RedirectURI:         request.Redirect,
		Scope:               request.Scope,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(config.Get().AuthAuthorizationCodeExpiration),
		Used:                false,
	}

	err = authcode.CreateAuthCode(code)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code insert. %v", err))
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", request.Redirect, code.Code, request.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
