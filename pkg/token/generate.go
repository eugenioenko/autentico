package token

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/user"
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

// GenerateTokens creates a signed access token and refresh token for the given user.
// cfg should be the per-client resolved config (via config.GetForClient) so that
// per-client overrides for expiration and audience are applied.
// OIDC Core §5.4: scope values control which claims are embedded in the access token.
func GenerateTokens(user user.User, clientID string, scope string, cfg *config.Config) (*AuthToken, error) {
	bs := config.GetBootstrap()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(cfg.AuthAccessTokenExpiration).UTC()
	refreshTokenExpiresAt := time.Now().Add(cfg.AuthRefreshTokenExpiration).UTC()

	// RFC 9068 §2.2: aud MUST identify the resource server(s) the token is intended for.
	// Always include the issuer and client_id; custom per-client audiences are appended.
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

	// Embed groups claim when "groups" scope was requested
	if containsScope(scope, "groups") {
		groupNames, err := group.GroupNamesByUserID(user.ID)
		if err == nil && len(groupNames) > 0 {
			accessClaims["groups"] = groupNames
		}
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
// OIDC Core §3.1.3.6: at_hash SHOULD be included when the ID token is issued from the token endpoint.
// The scope parameter controls which optional claims are included.
func GenerateIDToken(user user.User, sessionID string, nonce string, scope string, clientID string, authTime time.Time, accessToken string) (string, error) {
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

	// OIDC Core §3.1.3.6: at_hash is the base64url encoding of the left-most half of the
	// hash of the access token value. SHA-256 is used for RS256 signed tokens.
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		claims["at_hash"] = base64.RawURLEncoding.EncodeToString(hash[:sha256.Size/2])
	}

	// OIDC Core §3.1.3.7: azp SHOULD be present when the ID token has a single audience
	if clientID != "" {
		claims["azp"] = clientID
	}

	// OIDC Core §5.4: profile scope grants access to name, preferred_username,
	// given_name, family_name, and other profile claims. §5.1: claims with empty
	// values are omitted rather than returned as null.
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

	// Embed groups claim when "groups" scope was requested
	if containsScope(scope, "groups") {
		groupNames, err := group.GroupNamesByUserID(user.ID)
		if err == nil && len(groupNames) > 0 {
			claims["groups"] = groupNames
		}
	}

	// OIDC Core §5.4: the AS MAY return email claims in the ID token when the
	// "email" scope was requested, even if they are also available via UserInfo.
	// Many RPs rely on ID token claims without calling UserInfo, so we include them here.
	if containsScope(scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.IsEmailVerified
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
// RFC 6749 §4.4: the client is the resource owner — sub is set to the client_id.
// No refresh token is generated (RFC 6749 §4.4.3).
func GenerateClientCredentialsToken(clientID string, scope string, cfg *config.Config) (*AuthToken, error) {
	bs := config.GetBootstrap()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(cfg.AuthAccessTokenExpiration).UTC()

	// RFC 9068 §2.2: aud MUST identify the resource server(s) the token is intended for.
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

// removeScope removes a specific scope from a space-separated scope string.
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
