package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"autentico/pkg/auth"
	"autentico/pkg/config"
	"autentico/pkg/models"
	. "autentico/pkg/models"
	"autentico/pkg/sessions"
	"autentico/pkg/tokens"
	"autentico/pkg/utils"
)

// @Summary Logins a user
// @Description Logins the user. Creates an accessToken and a refreshToken
// @Tags auth
// @Accept json
// @Produce json
// @Param user body UserLoginRequest true "User login payload"
// @Success 201 {object} ApiUserResponse
// @Router /login [post]

func LoginUser(w http.ResponseWriter, r *http.Request) {
	var request UserLoginRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		utils.ErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = ValidateUserLoginRequest(request)
	if err != nil {
		err = fmt.Errorf("User credentials error. %v", err)
		utils.ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	authToken, err := auth.LoginUser(request.Username, request.Password)
	if err != nil {
		utils.ErrorResponse(w, fmt.Sprintf("Login failed: %v", err), http.StatusInternalServerError)
		return
	}

	err = tokens.CreateToken(models.Token{
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
		err = fmt.Errorf("Token creation error. %v", err)
		utils.ErrorResponse(w, err.Error(), http.StatusBadRequest)
	}

	err = sessions.CreateSession(models.Session{
		ID:           authToken.SessionID,
		UserID:       authToken.UserID,
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    utils.GetClientIP(r),
		ExpiresAt:    authToken.AccessExpiresAt.UTC(),
	})

	if err != nil {
		err = fmt.Errorf("Session creation error. %v", err)
		utils.ErrorResponse(w, err.Error(), http.StatusBadRequest)
	}

	response := TokenResponse{
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(config.AuthAccessTokenExpiration / time.Second),
		Scope:        "read write",
	}

	// send the refresh token as secure cookie
	if config.AuthRefreshTokenAsSecureCookie {
		auth.SetRefreshTokenAsSecureCookie(w, response.RefreshToken)
		response.RefreshToken = ""
	}

	utils.SuccessResponse(w, response)
}
