package jwtutil

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	ZeroClaims
	UserID    string   `json:"sub"`
	Email     string   `json:"email"`
	SessionID string   `json:"sid"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	Audience  []string `json:"aud"`
	Issuer    string   `json:"iss"`
	Scope     string   `json:"scope"`
}

func (a *AccessTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if a.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(a.ExpiresAt, 0)), nil
}

// ExtractAzp parses a JWT without signature verification and returns the "azp"
// (authorized party) claim. Used to determine which client a token was issued to
// before performing ownership checks. Returns "" if the claim is absent or the
// token is malformed — callers should treat missing azp as "skip the check".
func ExtractAzp(tokenString string) string {
	claims := jwt.MapClaims{}
	// Parse without key function — we only need the claims, not verification.
	// The token has already been validated or will be looked up in the DB.
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return ""
	}
	if azp, ok := claims["azp"].(string); ok {
		return azp
	}
	return ""
}

// ValidateAudience checks if the token's audience matches any of the required audiences.
// If requiredAudiences is empty, audience validation is skipped (no restriction).
func ValidateAudience(tokenAud []string, requiredAudiences []string) error {
	if len(requiredAudiences) == 0 {
		return nil
	}
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
	}, jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	if err := ValidateAudience(claims.Audience, config.Get().AuthAccessTokenAudience); err != nil {
		return nil, err
	}
	return claims, nil
}
