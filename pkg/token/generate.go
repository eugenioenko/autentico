package token

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/user"
)

func GenerateTokens(user user.User) (*AuthToken, error) {
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	refreshTokenExpiresAt := time.Now().Add(config.Get().AuthRefreshTokenExpiration).UTC()

	accessClaims := jwt.MapClaims{
		"exp":       accessTokenExpiresAt.Unix(),
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Unix(),
		"jti":       xid.New().String(),
		"iss":       config.Get().AppAuthIssuer,
		"aud":       config.Get().AuthAccessTokenAudience,
		"sub":       user.ID,
		"typ":       "Bearer",
		"azp":       config.Get().AuthDefaultClientID,
		"sid":       sessionID,
		"acr":       "password",
		"realm_access": map[string]interface{}{
			"roles": config.Get().AuthRealmAccessRoles,
		},
		"scope":              "openid profile email",
		"email_verified":     false,
		"name":               user.Username,
		"preferred_username": user.Username,
		"given_name":         user.Username,
		"family_name":        user.Username,
		"email":              user.Email,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.Get().AuthJwkCertKeyID
	signedAccessToken, err := accessToken.SignedString(key.GetPrivateKey())
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
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.Get().AuthRefreshTokenSecret))
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
		Name:     config.Get().AuthRefreshTokenCookieName,
		Value:    refreshToken,
		Expires:  time.Now().Add(config.Get().AuthRefreshTokenExpiration),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode, // Helps mitigate CSRF attacks
		Path:     "/",
	})
}
