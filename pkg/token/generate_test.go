package token

import (
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
	config.Values.AuthAccessTokenSecret = "test-secret"
	config.Values.AuthRefreshTokenSecret = "test-secret"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	tokens, err := GenerateTokens(testUser)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, testUser.ID, tokens.UserID)
	assert.WithinDuration(t, time.Now().Add(config.Values.AuthAccessTokenExpiration), tokens.AccessExpiresAt, time.Minute)
	assert.WithinDuration(t, time.Now().Add(config.Values.AuthRefreshTokenExpiration), tokens.RefreshExpiresAt, time.Minute)
}

func TestGenerateIDToken_WithNonce(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Values.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	idToken, err := GenerateIDToken(testUser, "session-1", "test-nonce-123", "openid profile email", "my-client")
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
	assert.Equal(t, "testuser@example.com", claims["email"])
	assert.Equal(t, false, claims["email_verified"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["auth_time"])
}

func TestGenerateIDToken_WithoutNonce(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Values.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)

	assert.Equal(t, "user-1", claims["sub"])
	assert.Nil(t, claims["nonce"], "nonce should not be present when empty")
}

func TestGenerateIDToken_ScopeBasedClaims(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Values.AppAuthIssuer = "http://localhost/oauth2"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	// Only "openid" scope — should still include profile and email (openid implies them)
	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid", "my-client")
	require.NoError(t, err)
	claims := parseIDTokenClaims(t, idToken)
	assert.Equal(t, "testuser", claims["name"])
	assert.Equal(t, "testuser@example.com", claims["email"])
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
