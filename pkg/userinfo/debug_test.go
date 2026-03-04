package userinfo

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/stretchr/testify/assert"
)

func TestTokenValidation_Manual(t *testing.T) {
	claims := &jwtutil.AccessTokenClaims{
		UserID:    "u1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	parsed, err := jwtutil.ValidateAccessToken(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, "u1", parsed.UserID)
}
