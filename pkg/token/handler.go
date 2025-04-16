package token

import (
	"encoding/json"
	"fmt"
	"net/http"

	"autentico/pkg/model"
	"autentico/pkg/utils"
)

func HandleToken(w http.ResponseWriter, r *http.Request) {
	var request model.LoginRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		utils.ErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = model.ValidateLoginRequest(request)
	if err != nil {
		err = fmt.Errorf("User credentials error. %v", err)
		utils.ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	/*
		authToken, err := login.LoginUser(request.Username, request.Password)
		if err != nil {
			utils.ErrorResponse(w, fmt.Sprintf("Login failed: %v", err), http.StatusInternalServerError)
			return
		}

		err = CreateToken(model.Token{
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

		err = session.CreateSession(model.Session{
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

		response := model.TokenResponse{
			AccessToken:  authToken.AccessToken,
			RefreshToken: authToken.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(config.Get().AuthAccessTokenExpiration / time.Second),
			Scope:        "read write",
		}

		// send the refresh token as secure cookie
		if config.Get().AuthRefreshTokenAsSecureCookie {
			token.SetRefreshTokenAsSecureCookie(w, response.RefreshToken)
			response.RefreshToken = ""
		}

		utils.SuccessResponse(w, response)
	*/
}
