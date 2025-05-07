package token

import (
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestDecodeToken_ValidToken(t *testing.T) {
	secretKey := "test_secret"
	claims := &RefreshTokenClaims{
		UserID:    "user123",
		SessionID: "session123",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	assert.NoError(t, err)

	decodedClaims, err := DecodeRefreshToken(signedToken, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, claims.UserID, decodedClaims.UserID)
	assert.Equal(t, claims.SessionID, decodedClaims.SessionID)
}

func TestDecodeToken_ExpiredToken(t *testing.T) {
	secretKey := "test_secret"
	claims := &RefreshTokenClaims{
		UserID:    "user123",
		SessionID: "session123",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	assert.NoError(t, err)

	_, err = DecodeRefreshToken(signedToken, secretKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token has expired")
}

func TestDecodeToken_InvalidSignature(t *testing.T) {
	secretKey := "test_secret"
	wrongKey := "wrong_secret"
	claims := &RefreshTokenClaims{
		UserID:    "user123",
		SessionID: "session123",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	assert.NoError(t, err)

	_, err = DecodeRefreshToken(signedToken, wrongKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature is invalid")
}

func TestDecodeToken_InvalidTokenFormat(t *testing.T) {
	secretKey := "test_secret"
	invalidToken := "invalid.token.format"

	res, err := DecodeRefreshToken(invalidToken, secretKey)
	fmt.Println(res)
	assert.Error(t, err)
}
