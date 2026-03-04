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

func TestValidateAccessToken_AudienceMismatch(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccessTokenAudience = []string{"expected-aud"}
	})

	claims := &AccessTokenClaims{
		UserID:    "user-1",
		SessionID: "sess-1",
		Audience:  []string{"wrong-aud"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(key.GetPrivateKey())

	_, err := ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token audience")
}
