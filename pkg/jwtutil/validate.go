package jwtutil

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
)

type AccessTokenClaims struct {
	UserID    string   `json:"sub"`
	Email     string   `json:"email"`
	SessionID string   `json:"sid"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	Audience  []string `json:"aud"`
	Issuer    string   `json:"iss"`
}

func (a *AccessTokenClaims) Valid() error {
	if a.ExpiresAt == 0 {
		return fmt.Errorf("token missing exp")
	}
	if a.ExpiresAt < jwt.TimeFunc().Unix() {
		return fmt.Errorf("token has expired")
	}
	return nil
}

// ValidateAudience checks if the token's audience matches any of the required audiences
func ValidateAudience(tokenAud []string, requiredAudiences []string) error {
	for _, aud := range tokenAud {
		for _, required := range requiredAudiences {
			if aud == required {
				return nil
			}
		}
	}
	return fmt.Errorf("invalid token audience")
}

// ValidateAccessToken parses and validates an access token, returning its claims. It always uses the configured secret and validates the audience.
func ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	publicKey := key.GetPublicKey()
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if err := ValidateAudience(claims.Audience, config.Get().AuthAccessTokenAudience); err != nil {
		return nil, err
	}
	return claims, nil
}
