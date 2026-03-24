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

// GenerateTokens creates a signed access token and refresh token for the given user.
// cfg should be the per-client resolved config (via config.GetForClient) so that
// per-client overrides for expiration and audience are applied.
func GenerateTokens(user user.User, clientID string, cfg *config.Config) (*AuthToken, error) {
	bs := config.GetBootstrap()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(cfg.AuthAccessTokenExpiration).UTC()
	refreshTokenExpiresAt := time.Now().Add(cfg.AuthRefreshTokenExpiration).UTC()

	accessClaims := jwt.MapClaims{
		"exp":       accessTokenExpiresAt.Unix(),
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Unix(),
		"jti":       xid.New().String(),
		"iss":       bs.AppAuthIssuer,
		"aud":       cfg.AuthAccessTokenAudience,
		"sub":       user.ID,
		"typ":       "Bearer",
		"azp":       clientID,
		"sid":       sessionID,
		"acr":       "password",
		"scope":              "openid profile email",
		"email_verified":     false,
		"name":               user.Username,
		"preferred_username": user.Username,
		"given_name":         user.Username,
		"family_name":        user.Username,
		"email":              user.Email,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = bs.AuthJwkCertKeyID
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
	signedRefreshToken, err := refreshToken.SignedString([]byte(bs.AuthRefreshTokenSecret))
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
	bs := config.GetBootstrap()
	now := time.Now()
	idTokenExpiresAt := now.Add(config.Get().AuthAccessTokenExpiration).UTC()

	claims := jwt.MapClaims{
		"iss":       bs.AppAuthIssuer,
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

	if clientID != "" {
		claims["azp"] = clientID
	}

	// Include profile claims only when "profile" scope is explicitly requested
	if containsScope(scope, "profile") {
		claims["name"] = user.Username
		claims["preferred_username"] = user.Username
	}

	// Include email claims only when "email" scope is explicitly requested
	if containsScope(scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = false
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken.Header["kid"] = bs.AuthJwkCertKeyID

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

func SetRefreshTokenCookie(w http.ResponseWriter, refreshToken string) {
	bs := config.GetBootstrap()
	http.SetCookie(w, &http.Cookie{
		Name:     bs.AuthRefreshTokenCookieName,
		Value:    refreshToken,
		Expires:  time.Now().Add(config.Get().AuthRefreshTokenExpiration),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}
