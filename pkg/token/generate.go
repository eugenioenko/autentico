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
// OIDC Core §5.4: scope values control which claims are embedded in the access token.
func GenerateTokens(user user.User, clientID string, scope string, cfg *config.Config) (*AuthToken, error) {
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
		"acr":       "1",
		"scope":     scope,
	}

	// OIDC Core §5.4: only embed profile claims when "profile" scope was requested
	if containsScope(scope, "profile") {
		accessClaims["name"] = user.Username
		accessClaims["preferred_username"] = user.Username
		accessClaims["given_name"] = user.GivenName
		accessClaims["family_name"] = user.FamilyName
	}

	// OIDC Core §5.4: only embed email claims when "email" scope was requested
	if containsScope(scope, "email") {
		accessClaims["email"] = user.Email
		accessClaims["email_verified"] = user.IsEmailVerified
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
		"azp": clientID,
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
// OIDC Core §3.1.3.3: the ID token MUST contain iss, sub, aud, exp, iat.
// OIDC Core §3.1.3.3: nonce MUST be present if sent in the authorization request.
// The scope parameter controls which optional claims are included.
func GenerateIDToken(user user.User, sessionID string, nonce string, scope string, clientID string, authTime time.Time) (string, error) {
	bs := config.GetBootstrap()
	now := time.Now()
	idTokenExpiresAt := now.Add(config.Get().AuthAccessTokenExpiration).UTC()

	// OIDC Core §3.1.3.3: required claims — iss, sub, aud, exp, iat
	claims := jwt.MapClaims{
		"iss":       bs.AppAuthIssuer,
		"sub":       user.ID,
		"aud":       clientID, // OIDC Core §3.1.3.3: aud MUST contain the client_id
		"exp":       idTokenExpiresAt.Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),
		"sid":       sessionID,
		"acr":       "1", // OIDC Core §2: Authentication Context Class Reference
	}

	// OIDC Core §3.1.3.3: nonce MUST be present in ID token if sent in the authorization request
	if nonce != "" {
		claims["nonce"] = nonce
	}

	// OIDC Core §3.1.3.7: azp SHOULD be present when the ID token has a single audience
	if clientID != "" {
		claims["azp"] = clientID
	}

	// Include profile claims only when "profile" scope is explicitly requested
	if containsScope(scope, "profile") {
		claims["name"] = user.Username
		claims["preferred_username"] = user.Username
	}

	// Email claims are intentionally excluded from the id_token.
	// Per OIDC Core §5.4, scope=email grants access to email via the userinfo endpoint;
	// it does not require email to be present in the id_token.

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
