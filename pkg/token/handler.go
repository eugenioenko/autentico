package token

import (
	"fmt"
	"net/http"
	"time"

	authcode "autentico/pkg/auth_code"
	"autentico/pkg/config"
	"autentico/pkg/session"
	"autentico/pkg/user"
	"autentico/pkg/utils"
)

func HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Only POST method is allowed")
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	request := TokenRequest{
		GrantType:   r.FormValue("grant_type"),
		Code:        r.FormValue("code"),
		RedirectURI: r.FormValue("redirect_uri"),
		ClientID:    r.FormValue("client_id"),
		Username:    r.FormValue("username"),
		Password:    r.FormValue("password"),
	}

	err = ValidateTokenRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return
	}

	var usr *user.User

	if request.GrantType == "authorization_code" {
		err = ValidateTokenRequestAuthorizationCode(request)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
			return
		}

		code, err := authcode.AuthCodeByCode(request.Code)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("%v", err))
			return
		}

		if code == nil || code.Used || code.RedirectURI != request.RedirectURI || time.Now().After(code.ExpiresAt) {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid or has already been used")
			return
		}

		err = authcode.MarkAuthCodeAsUsed(request.Code)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Failed to mark authorization code as used: %v", err))
			return
		}

		usr, err = user.UserByID(code.UserID)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
			return
		}
	} else if request.GrantType == "password" {
		err = ValidateTokenRequestPassword(request)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
			return
		}

		usr, err = user.AuthenticateUser(request.Username, request.Password)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", fmt.Sprintf("Invalid username or password: %v", err))
			return
		}
	}

	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "The provided grant type is not supported")
		return
	}

	authToken, err := GenerateTokens(*usr)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Token generation failed: %v", err))
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
		GrantType:             request.GrantType, // Use the correct grant type
	})

	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%v", err))
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%v", err))
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
