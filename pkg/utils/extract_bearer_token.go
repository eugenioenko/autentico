package utils

import "strings"

// ExtractBearerToken extracts the token from the Authorization header.
// The header should be in the format: "Bearer <token>".
func ExtractBearerToken(authHeader string) string {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
}
