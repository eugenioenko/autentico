package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	"autentico/pkg/auth"
	"autentico/pkg/config"
	. "autentico/pkg/models"
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
	var req UserLoginRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		utils.ErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = ValidateUserLoginRequest(req)
	if err != nil {
		err = fmt.Errorf("User credentials error. %w", err)
		utils.ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := auth.LoginUser(req.Username, req.Password)
	if err != nil {
		utils.ErrorResponse(w, fmt.Sprintf("Login failed: %v", err), http.StatusInternalServerError)
		return
	}

	// send the refresh token as secure cookie
	if config.AuthRefreshTokenAsSecureCookie {
		auth.SetRefreshTokenAsSecureCookie(w, response.RefreshToken)
		response.RefreshToken = ""
	}

	utils.SuccessResponse(w, response)
}
