package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// HashToken hashes every nonempty credential, including strings that already
// look like hashes. Empty means no refresh token (client_credentials).
func HashToken(token string) string {
	if token == "" {
		return ""
	}
	return HashSHA256(token)
}
