package token

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTokens(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Values.AuthRefreshTokenExpiration = 30 * 24 * time.Hour
	config.Bootstrap.AuthAccessTokenSecret = "test-secret"
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	tokens, err := GenerateTokens(testUser, "", "openid profile email", config.Get())
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, testUser.ID, tokens.UserID)
	assert.WithinDuration(t, time.Now().Add(config.Values.AuthAccessTokenExpiration), tokens.AccessExpiresAt, time.Minute)
	assert.WithinDuration(t, time.Now().Add(config.Values.AuthRefreshTokenExpiration), tokens.RefreshExpiresAt, time.Minute)
}

func TestGenerateIDToken_WithNonce(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{
		ID:              "user-1",
		Username:        "testuser",
		GivenName:       "Test",
		FamilyName:      "User",
		Email:           "testuser@example.com",
		IsEmailVerified: true,
	}

	idToken, err := GenerateIDToken(testUser, "session-1", "test-nonce-123", "openid profile email", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)
	assert.NotEmpty(t, idToken)

	// Parse and verify claims
	claims := parseIDTokenClaims(t, idToken)

	assert.Equal(t, "user-1", claims["sub"])
	assert.Equal(t, "http://localhost/oauth2", claims["iss"])
	assert.Equal(t, "my-client", claims["aud"])
	assert.Equal(t, "test-nonce-123", claims["nonce"])
	assert.Equal(t, "session-1", claims["sid"])
	assert.Equal(t, "testuser", claims["name"])
	assert.Equal(t, "testuser", claims["preferred_username"])
	assert.Equal(t, "Test", claims["given_name"])
	assert.Equal(t, "User", claims["family_name"])
	assert.Equal(t, "testuser@example.com", claims["email"], "email must be in id_token when email scope requested")
	assert.Equal(t, true, claims["email_verified"], "email_verified must be in id_token when email scope requested")
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["auth_time"])
}

func TestGenerateIDToken_WithoutNonce(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)

	assert.Equal(t, "user-1", claims["sub"])
	assert.Nil(t, claims["nonce"], "nonce should not be present when empty")
}

func TestGenerateIDToken_ScopeBasedClaims(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{
		ID:              "user-1",
		Username:        "testuser",
		GivenName:       "Test",
		FamilyName:      "User",
		Email:           "testuser@example.com",
		IsEmailVerified: true,
	}

	// Only "openid" scope — profile and email claims must NOT be included
	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)
	claims := parseIDTokenClaims(t, idToken)
	assert.Nil(t, claims["name"])
	assert.Nil(t, claims["preferred_username"])
	assert.Nil(t, claims["given_name"])
	assert.Nil(t, claims["family_name"])
	assert.Nil(t, claims["email"])
	assert.Nil(t, claims["email_verified"])

	// "openid profile" — profile claims included, email claims not
	idToken, err = GenerateIDToken(testUser, "session-1", "", "openid profile", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)
	claims = parseIDTokenClaims(t, idToken)
	assert.Equal(t, "testuser", claims["name"])
	assert.Equal(t, "testuser", claims["preferred_username"])
	assert.Equal(t, "Test", claims["given_name"])
	assert.Equal(t, "User", claims["family_name"])
	assert.Nil(t, claims["email"])
	assert.Nil(t, claims["email_verified"])

	// "openid email" — email claims included in id_token per OIDC §5.4 MAY clause
	idToken, err = GenerateIDToken(testUser, "session-1", "", "openid email", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)
	claims = parseIDTokenClaims(t, idToken)
	assert.Nil(t, claims["name"])
	assert.Nil(t, claims["given_name"])
	assert.Nil(t, claims["family_name"])
	assert.Equal(t, "testuser@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])

	// "openid profile email" — both profile and email claims in id_token
	idToken, err = GenerateIDToken(testUser, "session-1", "", "openid profile email", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)
	claims = parseIDTokenClaims(t, idToken)
	assert.Equal(t, "testuser", claims["name"])
	assert.Equal(t, "Test", claims["given_name"])
	assert.Equal(t, "User", claims["family_name"])
	assert.Equal(t, "testuser@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])
}

// OIDC Core §5.1: claims with empty values MUST be omitted rather than returned as null.
func TestGenerateIDToken_ProfileClaims_EmptyNamesOmitted(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		// GivenName and FamilyName intentionally empty
	}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid profile", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)
	claims := parseIDTokenClaims(t, idToken)

	assert.Equal(t, "testuser", claims["name"])
	assert.Equal(t, "testuser", claims["preferred_username"])
	assert.Nil(t, claims["given_name"], "empty given_name must be omitted per OIDC §5.1")
	assert.Nil(t, claims["family_name"], "empty family_name must be omitted per OIDC §5.1")
}

// Issue #9/#10: auth_time must reflect the original authentication time, not token issuance time
// Issue #11: acr claim must always be present in the id_token
func TestGenerateIDToken_AcrClaimPresent(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{ID: "user-1", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Equal(t, "1", claims["acr"], "acr claim must be present in id_token")
}

func TestGenerateIDToken_AuthTimeReflectsOriginalLogin(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{ID: "user-1", Username: "testuser"}

	originalLoginTime := time.Now().Add(-5 * time.Minute).Truncate(time.Second)

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client", originalLoginTime, "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)

	authTime := int64(claims["auth_time"].(float64))
	assert.Equal(t, originalLoginTime.Unix(), authTime, "auth_time must equal the original login time, not now")
	assert.NotEqual(t, time.Now().Unix(), authTime, "auth_time must not be the current time")
}

// TestGenerateIDToken_AtHashPresent verifies that the at_hash claim is correctly
// computed as base64url(left_half(SHA-256(access_token))) per OIDC Core §3.1.3.6.
func TestGenerateIDToken_AtHashPresent(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{ID: "user-1", Username: "testuser"}

	accessToken := "test-access-token-value"
	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client", time.Now(), accessToken)
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)

	// Manually compute expected at_hash: base64url(left_half(SHA-256(access_token)))
	hash := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(hash[:sha256.Size/2])

	assert.Equal(t, expected, claims["at_hash"], "OIDC Core §3.1.3.6: at_hash must be base64url(left_half(SHA-256(access_token)))")
}

// TestGenerateIDToken_AtHashAbsentWhenNoAccessToken verifies that at_hash is omitted
// when no access token is provided (e.g., edge cases where ID token is issued alone).
func TestGenerateIDToken_AtHashAbsentWhenNoAccessToken(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{ID: "user-1", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client", time.Now(), "")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Nil(t, claims["at_hash"], "at_hash must not be present when no access token is provided")
}

// TestGenerateTokens_ScopeFiltering verifies that the access token only embeds
// profile/email claims when the corresponding scope was requested.
// OIDC Core §5.4: scope values control which claims are made available.
func TestGenerateTokens_ScopeFiltering(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"

	testUser := user.User{ID: "user-1", Username: "testuser", Email: "test@example.com"}

	parseAccessClaims := func(t *testing.T, tok *AuthToken) jwt.MapClaims {
		t.Helper()
		parsed, err := jwt.Parse(tok.AccessToken, func(token *jwt.Token) (interface{}, error) {
			return key.GetPublicKey(), nil
		})
		require.NoError(t, err)
		return parsed.Claims.(jwt.MapClaims)
	}

	// openid only — no profile or email claims in access token
	tokens, err := GenerateTokens(testUser, "", "openid", config.Get())
	require.NoError(t, err)
	claims := parseAccessClaims(t, tokens)
	assert.Nil(t, claims["name"], "OIDC Core §5.4: name must not be in access token without profile scope")
	assert.Nil(t, claims["email"], "OIDC Core §5.4: email must not be in access token without email scope")
	assert.Nil(t, claims["email_verified"], "email_verified must not be present without email scope")

	// openid profile — profile claims included, email not
	tokens, err = GenerateTokens(testUser, "", "openid profile", config.Get())
	require.NoError(t, err)
	claims = parseAccessClaims(t, tokens)
	assert.NotNil(t, claims["name"], "name must be in access token with profile scope")
	assert.Nil(t, claims["email"], "email must not be present without email scope")

	// openid email — email claims included, profile not
	tokens, err = GenerateTokens(testUser, "", "openid email", config.Get())
	require.NoError(t, err)
	claims = parseAccessClaims(t, tokens)
	assert.Nil(t, claims["name"], "name must not be present without profile scope")
	assert.NotNil(t, claims["email"], "email must be in access token with email scope")

	// scope in access token must reflect requested scope, not hardcoded value
	assert.Equal(t, "openid email", claims["scope"], "scope claim must match requested scope")
}

// TestGenerateTokens_AcrValue verifies the access token uses a standard acr value.
// OIDC Core §2: acr SHOULD be an absolute URI or RFC 6711 registered name.
// "password" is non-standard; "1" is consistent with the ID token and acr_values_supported.
func TestGenerateTokens_AcrValue(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"

	testUser := user.User{ID: "user-1", Username: "testuser", Email: "test@example.com"}

	tokens, err := GenerateTokens(testUser, "", "openid", config.Get())
	require.NoError(t, err)

	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	assert.Equal(t, "1", claims["acr"], "OIDC Core §2: acr should be '1' for non-MFA user")
}

func TestGenerateTokens_AcrValueMfa(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"

	// User with verified TOTP should get acr "2"
	testUser := user.User{ID: "user-1", Username: "testuser", Email: "test@example.com", TotpVerified: true}

	tokens, err := GenerateTokens(testUser, "", "openid", config.Get())
	require.NoError(t, err)

	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	assert.Equal(t, "2", claims["acr"], "OIDC Core §2: acr should be '2' for MFA user")
}

func TestBuildAudience(t *testing.T) {
	// Base case: no custom audiences
	aud := buildAudience("https://auth.example.com", "my-client", nil)
	assert.Equal(t, []string{"https://auth.example.com", "my-client"}, aud)

	// With custom audiences
	aud = buildAudience("https://auth.example.com", "my-client", []string{"https://api.example.com"})
	assert.Equal(t, []string{"https://auth.example.com", "my-client", "https://api.example.com"}, aud)

	// Deduplication: custom audience matches issuer or client_id
	aud = buildAudience("https://auth.example.com", "my-client", []string{"https://auth.example.com", "https://api.example.com"})
	assert.Equal(t, []string{"https://auth.example.com", "my-client", "https://api.example.com"}, aud)

	// Empty custom audiences
	aud = buildAudience("https://auth.example.com", "my-client", []string{})
	assert.Equal(t, []string{"https://auth.example.com", "my-client"}, aud)
}

func TestGenerateTokens_AudContainsIssuerAndClientID(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"
	config.Bootstrap.AppAuthIssuer = "https://auth.example.com/oauth2"
	config.Values.AuthAccessTokenAudience = []string{}

	testUser := user.User{ID: "user-1", Username: "testuser", Email: "test@example.com"}
	tokens, err := GenerateTokens(testUser, "test-client", "openid", config.Get())
	require.NoError(t, err)

	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	// RFC 9068 §2.2: aud MUST identify the resource server(s)
	audRaw := claims["aud"].([]interface{})
	var aud []string
	for _, a := range audRaw {
		aud = append(aud, a.(string))
	}
	assert.Contains(t, aud, "https://auth.example.com/oauth2")
	assert.Contains(t, aud, "test-client")
}

func TestGenerateTokens_AudIncludesCustomAudiences(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"
	config.Bootstrap.AppAuthIssuer = "https://auth.example.com/oauth2"
	config.Values.AuthAccessTokenAudience = []string{"https://api.example.com"}

	testUser := user.User{ID: "user-1", Username: "testuser", Email: "test@example.com"}
	tokens, err := GenerateTokens(testUser, "test-client", "openid", config.Get())
	require.NoError(t, err)

	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	audRaw := claims["aud"].([]interface{})
	var aud []string
	for _, a := range audRaw {
		aud = append(aud, a.(string))
	}
	assert.Contains(t, aud, "https://auth.example.com/oauth2")
	assert.Contains(t, aud, "test-client")
	assert.Contains(t, aud, "https://api.example.com")
}

func TestContainsScope(t *testing.T) {
	assert.True(t, containsScope("openid profile email", "openid"))
	assert.True(t, containsScope("openid profile email", "profile"))
	assert.True(t, containsScope("openid profile email", "email"))
	assert.False(t, containsScope("openid profile email", "admin"))
	assert.False(t, containsScope("", "openid"))
	assert.True(t, containsScope("openid", "openid"))
}

// parseIDTokenClaims parses an ID token JWT and returns its claims.
// It validates the signature using the RSA public key.
func parseIDTokenClaims(t *testing.T, idToken string) jwt.MapClaims {
	t.Helper()

	parsed, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	return claims
}
