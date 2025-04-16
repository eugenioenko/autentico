package login

import (
	"fmt"
	"net/http"
	"time"

	authcode "autentico/pkg/auth_code"
	"autentico/pkg/config"
	"autentico/pkg/model"
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
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Only POST method is allowed",
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	// Parse the form data
	err := r.ParseForm()
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Request payload needs to be application/x-www-form-urlencoded",
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	request := model.LoginRequest{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		Redirect: r.FormValue("redirect"),
		State:    r.FormValue("state"),
	}

	err = model.ValidateLoginRequest(request)
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: fmt.Sprintf("user credentials error. %v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	usr, err := AuthenticateUser(request.Username, request.Password)
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: fmt.Sprintf("login failed. %v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusInternalServerError)
		return
	}

	authCode, err := authcode.GenerateSecureCode()
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: fmt.Sprintf("failed secure code generation. %v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusInternalServerError)
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
		response := model.AuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: fmt.Sprintf("failed secure code insert. %v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", request.Redirect, code.Code, request.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)

}
