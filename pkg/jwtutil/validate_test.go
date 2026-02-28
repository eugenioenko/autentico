package jwtutil

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestValidateAccessToken_Valid(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccessTokenAudience = []string{"test-audience"}
		config.Bootstrap.AppAuthIssuer = "test-issuer"
		config.Bootstrap.AuthJwkCertKeyID = "test-kid"
	})

	claims := jwt.MapClaims{
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   "test-issuer",
		"aud":   []string{"test-audience"},
		"sub":   "user-id",
		"typ":   "Bearer",
		"sid":   "session-id",
		"scope": "openid",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-kid"
	signedToken, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	result, err := ValidateAccessToken(signedToken)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "user-id", result.UserID)
	assert.Equal(t, "session-id", result.SessionID)
}

func TestValidateAccessToken_Expired(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccessTokenAudience = []string{"test-audience"}
		config.Bootstrap.AppAuthIssuer = "test-issuer"
	})

	claims := jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"iss": "test-issuer",
		"aud": []string{"test-audience"},
		"sub": "user-id",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	_, err = ValidateAccessToken(signedToken)
	assert.Error(t, err)
}

func TestValidateAccessToken_InvalidToken(t *testing.T) {
	_, err := ValidateAccessToken("not-a-valid-token")
	assert.Error(t, err)
}

func TestValidateAccessToken_WrongAudience(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccessTokenAudience = []string{"expected-audience"}
		config.Bootstrap.AppAuthIssuer = "test-issuer"
	})

	claims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"iss": "test-issuer",
		"aud": []string{"wrong-audience"},
		"sub": "user-id",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	_, err = ValidateAccessToken(signedToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token audience")
}

func TestValidateAudience_Match(t *testing.T) {
	err := ValidateAudience([]string{"aud1", "aud2"}, []string{"aud2"})
	assert.NoError(t, err)
}

func TestValidateAudience_NoMatch(t *testing.T) {
	err := ValidateAudience([]string{"aud1"}, []string{"aud2"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token audience")
}

func TestValidateAudience_EmptyTokenAud(t *testing.T) {
	// Token has no audience but one is required → fail
	err := ValidateAudience([]string{}, []string{"aud1"})
	assert.Error(t, err)
}

func TestValidateAudience_NoRequiredAudiences(t *testing.T) {
	// No audiences configured → skip validation (any token accepted)
	err := ValidateAudience([]string{}, []string{})
	assert.NoError(t, err)
	err = ValidateAudience([]string{"any-aud"}, []string{})
	assert.NoError(t, err)
}

func TestAccessTokenClaims_Valid(t *testing.T) {
	claims := &AccessTokenClaims{
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	assert.NoError(t, claims.Valid())
}

func TestAccessTokenClaims_MissingExp(t *testing.T) {
	claims := &AccessTokenClaims{
		ExpiresAt: 0,
	}
	err := claims.Valid()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token missing exp")
}

func TestAccessTokenClaims_Expired(t *testing.T) {
	claims := &AccessTokenClaims{
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}
	err := claims.Valid()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token has expired")
}
