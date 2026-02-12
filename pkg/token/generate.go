package token

import (
	"fmt"
	"net/http"
	"strings"
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

// GenerateIDToken creates an OIDC ID token JWT signed with RS256.
// The nonce parameter is included in the token if non-empty (for authorization code flow replay protection).
// The scope parameter controls which claims are included (e.g. "profile" adds name claims, "email" adds email claims).
func GenerateIDToken(user user.User, sessionID string, nonce string, scope string, clientID string) (string, error) {
	now := time.Now()
	idTokenExpiresAt := now.Add(config.Get().AuthAccessTokenExpiration).UTC()

	claims := jwt.MapClaims{
		"iss":       config.Get().AppAuthIssuer,
		"sub":       user.ID,
		"aud":       clientID,
		"exp":       idTokenExpiresAt.Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"sid":       sessionID,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	if clientID != "" && clientID != config.Get().AuthDefaultClientID {
		claims["azp"] = clientID
	}

	// Include profile claims when "profile" or "openid" scope is present
	if containsScope(scope, "profile") || containsScope(scope, "openid") {
		claims["name"] = user.Username
		claims["preferred_username"] = user.Username
	}

	// Include email claims when "email" or "openid" scope is present
	if containsScope(scope, "email") || containsScope(scope, "openid") {
		claims["email"] = user.Email
		claims["email_verified"] = false
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken.Header["kid"] = config.Get().AuthJwkCertKeyID

	signedIDToken, err := idToken.SignedString(key.GetPrivateKey())
	if err != nil {
		return "", fmt.Errorf("could not sign id token: %v", err)
	}

	return signedIDToken, nil
}

// containsScope checks if a space-separated scope string contains a specific scope value.
func containsScope(scopeStr string, target string) bool {
	scopes := strings.Split(scopeStr, " ")
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
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
