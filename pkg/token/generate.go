package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userclaim"
)

// acrForUser returns the Authentication Context Class Reference value.
// OIDC Core §2: "1" for single-factor (password), "2" for multi-factor (password + TOTP).
func acrForUser(u user.User) string {
	if u.TotpVerified {
		return "2"
	}
	return "1"
}

// buildAudience constructs the access token audience list.
// Always includes the issuer and client_id, plus any custom audiences from config.
func buildAudience(issuer string, clientID string, customAudiences []string) []string {
	seen := map[string]bool{issuer: true, clientID: true}
	aud := []string{issuer, clientID}
	for _, a := range customAudiences {
		if !seen[a] {
			seen[a] = true
			aud = append(aud, a)
		}
	}
	return aud
}

// addOpenCloudRoleClaim normalizes the optional opencloudRoles custom claim to
// the list shape expected by OpenCloud. If the claim is absent, Autentico's
// built-in user.Role is used as a single role. An explicit custom claim always
// takes precedence over the built-in role.
func addOpenCloudRoleClaim(claims map[string]interface{}, custom map[string]string, userRole string) {
	if raw, exists := custom["opencloudRoles"]; exists {
		var roles []string
		if err := json.Unmarshal([]byte(raw), &roles); err == nil && len(roles) > 0 {
			claims["opencloudRoles"] = roles
			return
		}
		if raw != "" {
			claims["opencloudRoles"] = []string{raw}
			return
		}
	}
	if userRole != "" {
		claims["opencloudRoles"] = []string{userRole}
	}
}

// GenerateTokens creates a signed access token and refresh token for the given user.
// cfg should be the per-client resolved config (via config.GetForClient) so that
// per-client overrides for expiration and audience are applied.
// OIDC Core §5.4: scope values control which claims are embedded in the access token.
func GenerateTokens(user user.User, clientID string, scope string, cfg *config.Config) (*AuthToken, error) {
	bs := config.GetBootstrap()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(cfg.AuthAccessTokenExpiration).UTC()
	refreshTokenExpiresAt := time.Now().Add(cfg.AuthRefreshTokenExpiration).UTC()
	aud := buildAudience(bs.AppAuthIssuer, clientID, cfg.AuthAccessTokenAudience)

	accessClaims := jwt.MapClaims{
		"exp":       accessTokenExpiresAt.Unix(),
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Unix(),
		"jti":       xid.New().String(),
		"iss":       bs.AppAuthIssuer,
		"aud":       aud,
		"sub":       user.ID,
		"typ":       "Bearer",
		"azp":       clientID,
		"sid":       sessionID,
		"acr":       acrForUser(user),
		"scope":     scope,
		"role":      user.Role,
	}

	if containsScope(scope, "profile") {
		accessClaims["name"] = user.Username
		accessClaims["preferred_username"] = user.Username
	}
	if containsScope(scope, "email") {
		accessClaims["email"] = user.Email
		accessClaims["email_verified"] = user.IsEmailVerified
	}
	if containsScope(scope, "groups") {
		groupNames, err := group.GroupNamesByUserID(user.ID)
		if err == nil && len(groupNames) > 0 {
			accessClaims["groups"] = groupNames
		}
	}
	if containsScope(scope, "custom_claims") {
		custom, err := userclaim.ClaimMapByUserID(user.ID)
		if err != nil {
			return nil, fmt.Errorf("could not load custom claims: %w", err)
		}
		addOpenCloudRoleClaim(accessClaims, custom, user.Role)
		for name, value := range custom {
			if name == "opencloudRoles" {
				continue
			}
			if _, taken := accessClaims[name]; !taken {
				accessClaims[name] = value
			}
		}
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = bs.AuthJwkCertKeyID
	signedAccessToken, err := accessToken.SignedString(key.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("could not sign access token: %v", err)
	}

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

	return &AuthToken{
		UserID:           user.ID,
		AccessToken:      signedAccessToken,
		RefreshToken:     signedRefreshToken,
		SessionID:        sessionID,
		AccessExpiresAt:  accessTokenExpiresAt,
		RefreshExpiresAt: refreshTokenExpiresAt,
	}, nil
}

// GenerateIDToken creates an OIDC ID token JWT signed with RS256.
func GenerateIDToken(user user.User, sessionID string, nonce string, scope string, clientID string, authTime time.Time, accessToken string) (string, error) {
	bs := config.GetBootstrap()
	now := time.Now()
	idTokenExpiresAt := now.Add(config.Get().AuthAccessTokenExpiration).UTC()
	claims := jwt.MapClaims{
		"iss":       bs.AppAuthIssuer,
		"sub":       user.ID,
		"aud":       clientID,
		"exp":       idTokenExpiresAt.Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),
		"sid":       sessionID,
		"acr":       "1",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		claims["at_hash"] = base64.RawURLEncoding.EncodeToString(hash[:sha256.Size/2])
	}
	if clientID != "" {
		claims["azp"] = clientID
	}
	if containsScope(scope, "profile") {
		claims["name"] = user.Username
		claims["preferred_username"] = user.Username
		if user.GivenName != "" {
			claims["given_name"] = user.GivenName
		}
		if user.FamilyName != "" {
			claims["family_name"] = user.FamilyName
		}
	}
	if containsScope(scope, "groups") {
		groupNames, err := group.GroupNamesByUserID(user.ID)
		if err == nil && len(groupNames) > 0 {
			claims["groups"] = groupNames
		}
	}
	if containsScope(scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.IsEmailVerified
	}
	if containsScope(scope, "custom_claims") {
		custom, err := userclaim.ClaimMapByUserID(user.ID)
		if err != nil {
			return "", fmt.Errorf("could not load custom claims: %w", err)
		}
		addOpenCloudRoleClaim(claims, custom, user.Role)
		for name, value := range custom {
			if name == "opencloudRoles" {
				continue
			}
			if _, taken := claims[name]; !taken {
				claims[name] = value
			}
		}
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken.Header["kid"] = bs.AuthJwkCertKeyID
	signedIDToken, err := idToken.SignedString(key.GetPrivateKey())
	if err != nil {
		return "", fmt.Errorf("could not sign id token: %v", err)
	}
	return signedIDToken, nil
}

// GenerateClientCredentialsToken creates a signed access token for a client_credentials grant.
func GenerateClientCredentialsToken(clientID string, scope string, cfg *config.Config) (*AuthToken, error) {
	bs := config.GetBootstrap()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(cfg.AuthAccessTokenExpiration).UTC()
	aud := buildAudience(bs.AppAuthIssuer, clientID, cfg.AuthAccessTokenAudience)
	accessClaims := jwt.MapClaims{
		"exp":       accessTokenExpiresAt.Unix(),
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Unix(),
		"jti":       xid.New().String(),
		"iss":       bs.AppAuthIssuer,
		"aud":       aud,
		"sub":       clientID,
		"typ":       "Bearer",
		"azp":       clientID,
		"sid":       sessionID,
		"acr":       "1",
		"scope":     scope,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = bs.AuthJwkCertKeyID
	signedAccessToken, err := accessToken.SignedString(key.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("could not sign access token: %v", err)
	}
	return &AuthToken{
		UserID:          "",
		AccessToken:     signedAccessToken,
		RefreshToken:    "",
		SessionID:       sessionID,
		AccessExpiresAt: accessTokenExpiresAt,
	}, nil
}

func removeScope(scopeStr string, target string) string {
	scopes := strings.Fields(scopeStr)
	var result []string
	for _, s := range scopes {
		if s != target {
			result = append(result, s)
		}
	}
	return strings.Join(result, " ")
}

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
