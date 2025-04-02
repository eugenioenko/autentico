package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	"autentico/pkg/config"
	. "autentico/pkg/models"
)

func GenerateTokens(user User) (string, string, error) {
	accessClaims := jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"email":    user.Email,
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(config.AuthAccessTokenExpiration).Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(config.AuthAccessTokenSecret))
	if err != nil {
		return "", "", fmt.Errorf("could not sign access token: %v", err)
	}

	// Refresh Token
	refreshClaims := jwt.MapClaims{
		"sub": user.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(config.AuthRefreshTokenExpiration).Unix(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.AuthRefreshTokenSecret))
	if err != nil {
		return "", "", fmt.Errorf("could not sign refresh token: %v", err)
	}

	return signedAccessToken, signedRefreshToken, nil
}

func SetRefreshTokenAsSecureCookie(w http.ResponseWriter, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.AuthRefreshTokenCookieName,
		Value:    refreshToken,
		Expires:  time.Now().Add(config.AuthRefreshTokenExpiration),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode, // Helps mitigate CSRF attacks
		Path:     "/",
	})
}
