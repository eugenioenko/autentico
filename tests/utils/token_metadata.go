package testutils

import "github.com/golang-jwt/jwt/v5"

func fixtureClaims(raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	return claims, err
}

// StoredTokenClientID supplies metadata when tests insert signed JWTs directly.
// Opaque fixture credentials have no claims and retain empty metadata.
func StoredTokenClientID(raw string) string {
	claims, err := fixtureClaims(raw)
	if err != nil {
		return ""
	}
	value, _ := claims["azp"].(string)
	return value
}

func StoredTokenACR(raw string) string {
	claims, err := fixtureClaims(raw)
	if err != nil {
		return ""
	}
	value, _ := claims["acr"].(string)
	return value
}
