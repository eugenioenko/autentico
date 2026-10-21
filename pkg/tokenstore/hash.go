package tokenstore

import (
	"crypto/sha256"
	"encoding/hex"
)

// Hash hashes every nonempty credential, including strings that already look
// like hashes. Empty means no refresh token (client_credentials).
func Hash(token string) string {
	if token == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
