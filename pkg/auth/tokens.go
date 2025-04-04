package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"

	"autentico/pkg/config"
	. "autentico/pkg/models"
)

func GenerateTokens(user User) (*AuthToken, error) {
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.AuthAccessTokenExpiration)
	refreshTokenExpiresAt := time.Now().Add(config.AuthRefreshTokenExpiration)

	accessClaims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"sid":   sessionID,
		"iat":   time.Now().Unix(),
		"exp":   accessTokenExpiresAt.Unix(),
		"aud":   config.AuthDefaultClientID,
		"iss":   config.AuthDefaultIssuer,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(config.AuthAccessTokenSecret))
	if err != nil {
		return nil, fmt.Errorf("could not sign access token: %v", err)
	}

	// Refresh Token
	refreshClaims := jwt.MapClaims{
		"sub": user.ID,
		"iat": time.Now().Unix(),
		"sid": sessionID,
		"exp": refreshTokenExpiresAt.Unix(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.AuthRefreshTokenSecret))
	if err != nil {
		return nil, fmt.Errorf("could not sign refresh token: %v", err)
	}

	result := &AuthToken{
		UserID:           user.ID,
		AccessToken:      signedAccessToken,
		RefreshToken:     signedRefreshToken,
		SessionID:        sessionID,
		AccessExpiresAt:  accessTokenExpiresAt,
		RefreshExpiresAt: refreshTokenExpiresAt,
	}

	return result, nil
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
