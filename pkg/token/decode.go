package token

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

func DecodeRefreshToken(tokenString string, secretKey string) (*RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}
