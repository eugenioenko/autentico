package token

import (
	"fmt"
	"net/http"
	"time"

	authcode "autentico/pkg/auth_code"
	"autentico/pkg/config"
	"autentico/pkg/model"
	"autentico/pkg/session"
	"autentico/pkg/user"
	"autentico/pkg/utils"
)

func HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Only POST method is allowed",
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	err := r.ParseForm()
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Request payload needs to be application/x-www-form-urlencoded",
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	request := TokenRequest{
		GrantType:   r.FormValue("grant_type"),
		Code:        r.FormValue("code"),
		RedirectURI: r.FormValue("redirect_uri"),
		ClientID:    r.FormValue("client_id"),
	}

	err = ValidateTokenRequest(request)
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: fmt.Sprintf("%v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	err = ValidateTokenRequestAuthorizationCode(request)
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: fmt.Sprintf("%v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	code, err := authcode.AuthCodeByCode(request.Code)
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: fmt.Sprintf("%v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	// TODO: validate that the auth_code hasn't been used and is valid
	// TODO: mark the auth_code as used

	usr, err := user.UserByID(code.UserID)
	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: fmt.Sprintf("%v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusBadRequest)
		return
	}

	authToken, err := GenerateTokens(*usr)
	if err != nil {
		utils.ErrorResponse(w, fmt.Sprintf("Login failed: %v", err), http.StatusInternalServerError)
		return
	}

	err = CreateToken(Token{
		UserID:                authToken.UserID,
		AccessToken:           authToken.AccessToken,
		RefreshToken:          authToken.RefreshToken,
		AccessTokenType:       "Bearer",
		RefreshTokenExpiresAt: authToken.RefreshExpiresAt,
		AccessTokenExpiresAt:  authToken.AccessExpiresAt,
		IssuedAt:              time.Now().UTC(),
		Scope:                 "read write",
		GrantType:             "password",
	})

	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: fmt.Sprintf("%v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusInternalServerError)
		return
	}

	err = session.CreateSession(session.Session{
		ID:           authToken.SessionID,
		UserID:       authToken.UserID,
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    utils.GetClientIP(r),
		ExpiresAt:    authToken.AccessExpiresAt.UTC(),
	})

	if err != nil {
		response := model.AuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: fmt.Sprintf("%v", err),
		}
		utils.WriteApiResponse(w, response, http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(config.Get().AuthAccessTokenExpiration / time.Second),
		Scope:        "read write",
	}

	// send the refresh token as secure cookie
	if config.Get().AuthRefreshTokenAsSecureCookie {
		SetRefreshTokenAsSecureCookie(w, response.RefreshToken)
		response.RefreshToken = ""
	}

	utils.WriteApiResponse(w, response, http.StatusOK)

}
