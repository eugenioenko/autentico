package login

import (
	"fmt"
	"net/http"
	"time"

	authcode "autentico/pkg/auth_code"
	"autentico/pkg/config"
	"autentico/pkg/user"
	"autentico/pkg/utils"
)

// @Summary Logins a user
// @Description Logins the user. Creates an accessToken and a refreshToken
// @Tags auth
// @Accept json
// @Produce json
// @Param user body LoginRequest true "User login payload"
// @Success 201 {object} ApiUserResponse
// @Router /login [post]

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
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		Redirect: r.FormValue("redirect"),
		State:    r.FormValue("state"),
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("login failed. %v", err))
		return
	}

	authCode, err := authcode.GenerateSecureCode()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code generation. %v", err))
		return
	}

	code := authcode.AuthCode{
		Code:        authCode,
		UserID:      usr.ID,
		RedirectURI: request.Redirect,
		Scope:       "read write", // TODO set this scope correctly
		ExpiresAt:   time.Now().Add(config.Get().AuthAuthorizationCodeExpiration),
		Used:        false,
	}

	err = authcode.CreateAuthCode(code)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("failed secure code insert. %v", err))
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", request.Redirect, code.Code, request.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
