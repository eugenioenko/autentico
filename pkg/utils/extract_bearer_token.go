package utils

import "strings"

// ExtractBearerToken extracts the token from the Authorization header.
// RFC 6750 §2.1 / RFC 7235 §2.1: the authentication scheme name ("Bearer") is
// case-insensitive, so "bearer", "BEARER", and "Bearer" are all valid.
func ExtractBearerToken(authHeader string) string {
	if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(authHeader[7:])
}
